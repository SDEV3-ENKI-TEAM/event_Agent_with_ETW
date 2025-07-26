#pragma warning disable CA1416
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;   // ★ Kernel ETW
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;

/* ─────  Namespace  ───── */
namespace EventAgentUnified
{
    internal class Program
    {
        /* ───── Sysmon Provider ───── */
        private const string SysmonProvider = "Microsoft-Windows-Sysmon";
        private const ulong   SysmonKeywords = ulong.MaxValue;
        private const TraceEventLevel SysmonLevel = TraceEventLevel.Informational;

        /* ───── ETW 세션 이름 ───── */
        private const string EtwSessionName = "EventAgent_ETW";

        /* ───── Security(EventLog) 필터 ───── */
        private static readonly int[] SecurityIds = { 4688, 4689, 4624, 4625 };

        /* ───── OpenTelemetry ───── */
        private static readonly ActivitySource Src = new("event.agent");
        private static readonly TracerProvider Otel =
            Sdk.CreateTracerProviderBuilder()
               .SetResourceBuilder(ResourceBuilder.CreateDefault()
                   .AddService("event-agent"))
               .AddSource("event.agent")
               .AddOtlpExporter(o =>
               {
                   o.Endpoint = new("http://localhost:4319");
                   o.Protocol = OtlpExportProtocol.Grpc;
               })
               .Build();

        /* ───── Root Span 관리 ───── */
        private record RootInfo(Activity Act, DateTime Ts);
        private static readonly ConcurrentDictionary<int, RootInfo> Roots = new();
        private static readonly TimeSpan ROOT_TIMEOUT = TimeSpan.FromSeconds(60);

        /* ───────────────────────── Main ───────────────────────── */
        private static void Main()
        {
            if (!(TraceEventSession.IsElevated() ?? false))
            {
                Console.WriteLine("[!] 관리자 권한으로 실행하세요.");
                return;
            }
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine("[Agent] Sysmon + Kernel-Process + Security 수집 시작 — <Enter> 로 종료\n");

            /* ── 1. ETW 세션 ── */
            using var sess = new TraceEventSession(EtwSessionName) { StopOnDispose = true };

            /* Kernel-Process (프로세스 시작/종료) */
            sess.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);
            /* Sysmon */
            sess.EnableProvider(SysmonProvider, SysmonLevel, SysmonKeywords);
            

            /* 이벤트 핸들러 등록 */
            sess.Source.AllEvents       += HandleEtwEvent;     // Sysmon 고정
            sess.Source.Dynamic.All     += HandleEtwEvent;     // Sysmon 동적
            sess.Source.Kernel.ProcessStart += HandleKStart;
            sess.Source.Kernel.ProcessStop  += HandleKStop;

            var etwTh = new Thread(() => sess.Source.Process()) { IsBackground = true };
            etwTh.Start();

            /* ── 2. Security EventLog ── */
            using var secWatcher = StartSecurityWatcher();

            /* ── 3. Root Span 타임아웃 sweeper ── */
            using var timer = new Timer(_ => SweepRoots(), null, ROOT_TIMEOUT, ROOT_TIMEOUT);

            Console.ReadLine();

            /* ─ 종료 ─ */
            sess.Dispose();
            secWatcher.Enabled = false;
            Otel.Dispose();
            etwTh.Join();
        }

        /* ─────────────── Kernel-Process Start/Stop ─────────────── */
        private static void HandleKStart(ProcessTraceData e)
        {
            /* 중복 Root 방지 */
            if (Roots.ContainsKey(e.ProcessID)) return;

            var root = Src.StartActivity($"process:{e.ProcessID}", ActivityKind.Internal);
            if (root == null) return;

            root.SetTag("provider", "Kernel-Process");
            root.SetTag("event.id", 1);
            root.SetTag("pid", e.ProcessID);
            root.SetTag("ppid", e.ParentID);
            root.SetTag("Image", e.ProcessName);
            root.SetTag("CommandLine", e.CommandLine);

            Roots[e.ProcessID] = new(root, DateTime.UtcNow);

            Console.WriteLine($"[Kernel] Start PID {e.ProcessID} PPID {e.ParentID}");
        }

        private static void HandleKStop(ProcessTraceData e) => CloseRoot(e.ProcessID, provider:"Kernel-Process", eid:2);

        /* ─────────────── Sysmon ETW(고정+동적) ─────────────── */
        private static void HandleEtwEvent(TraceEvent ev)
        {
            if (ev.ProviderName != SysmonProvider) return;           // Sysmon 전용

            int pid  = TryGetPayloadInt(ev, "ProcessId") ?? ev.ProcessID;
            int ppid = TryGetPayloadInt(ev, "ParentProcessId") ?? 0;
            if (pid == 0) return;

            /* ① Root 확보 (없으면 이미 Kernel Start가 만들었을 것) */
            var root = Roots.GetOrAdd(pid, _ =>
            {
                var r = Src.StartActivity($"process:{pid}", ActivityKind.Internal);
                if (r != null)
                {
                    r.SetTag("provider", "Sysmon");
                    r.SetTag("event.id", 1);
                    r.SetTag("pid",  pid);
                    r.SetTag("ppid", ppid);
                }
                return new RootInfo(r!, DateTime.UtcNow);
            }).Act;

            if (root == null) return;   // 생성 실패 시

            /* ② Child Span */
            using var span = Src.StartActivity($"evt:{ev.ID}", ActivityKind.Internal,
                                    parentContext: root.Context);
            if (span == null) return;

            span.SetTag("provider", "Sysmon");
            span.SetTag("event.id", (int)ev.ID);
            AddTags(span, ev, pid, ppid);

            /* ③ 종료 이벤트면 Root 닫기 */
            if ((int)ev.ID == 5) CloseRoot(pid, "Sysmon", 5);
        }

        /* ─────────────── Security EventLog ─────────────── */
private static EventLogWatcher StartSecurityWatcher()
{
    var q = new EventLogQuery("Security", PathType.LogName) { TolerateQueryErrors = true };
    var w = new EventLogWatcher(q, null, false);
    w.EventRecordWritten += (_, e) =>
    {
        using var rec = e.EventRecord;
        if (rec == null || !SecurityIds.Contains(rec.Id)) return;

        int pid = rec.ProcessId ?? 0;

        /* 부모 Root Span 찾기 (있을 수도, 없을 수도) */
        RootInfo? parentInfo = null;
        if (pid != 0) Roots.TryGetValue(pid, out parentInfo);

        using var span = Src.StartActivity(
            $"sec:{rec.Id}",
            ActivityKind.Internal,
            parentContext: parentInfo?.Act?.Context ?? default);

        if (span == null) return;

        span.SetTag("provider", "Security");
        span.SetTag("event.id", rec.Id);
        span.SetTag("pid", pid);
        span.SetTag("TimeCreated", rec.TimeCreated);

        Console.WriteLine($"[Security] {rec.Id} PID {pid}");
    };
    w.Enabled = true;
    Console.WriteLine("[+] Security EventLogWatcher ON");
    return w;
}


        /* ─────────────── Root 종료 & 타임아웃 ─────────────── */
        private static void CloseRoot(int pid, string provider, int eid)
        {
            if (Roots.TryRemove(pid, out var info))
            {
                info.Act.SetTag("provider.close", provider);
                info.Act.SetTag("event.id",        eid);
                info.Act.Dispose();
                Console.WriteLine($"[RootClose] {provider} EID {eid} PID {pid}");
            }
        }

        private static void SweepRoots()
        {
            var now = DateTime.UtcNow;
            foreach (var (pid, ri) in Roots.ToArray())
                if (now - ri.Ts > ROOT_TIMEOUT)
                    CloseRoot(pid, "Timeout", 0);
        }

        /* ─────────────── Helper  ─────────────── */
        private static void AddTags(Activity act, TraceEvent ev, int pid, int ppid)
        {
            void T(string k, object? v) { if (v != null) act.SetTag(k, v); }

            T("pid", pid);
            if (ppid != 0) T("ppid", ppid);

            foreach (var n in ev.PayloadNames ?? Array.Empty<string>())
            {
                try { T(n, ev.PayloadByName(n)); } catch { }
            }
        }

        private static int? TryGetPayloadInt(TraceEvent ev, string field)
        {
            if (ev.PayloadNames?.Contains(field) != true) return null;
            try
            {
                return ev.PayloadByName(field) switch
                {
                    int i   => i,
                    long l  => (int)l,
                    string s when int.TryParse(s, out int v) => v,
                    _ => null
                };
            }
            catch { return null; }
        }
    }
}
