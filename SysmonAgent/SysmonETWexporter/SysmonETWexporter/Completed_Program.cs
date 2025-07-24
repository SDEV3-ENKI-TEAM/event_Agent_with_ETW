#pragma warning disable CA1416
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Text;
using System.Threading;
using System.Reflection;
using System.Xml;

namespace EventAgentBMode // Sysmon=ETW, Security=EventLogWatcher
{
    internal class Program
    {
        /* ───── Sysmon (ETW) 설정 ───── */
        private const string SysmonProvider = "Microsoft-Windows-Sysmon";
        private const ulong   SysmonKeywords = ulong.MaxValue;
        private const TraceEventLevel SysmonLevel = TraceEventLevel.Informational;
        private const string EtwSessionName = "EventAgent_ETW";

        /* ───── Security(EventLog) 설정 ───── */
        private static readonly HashSet<int> SecurityIds = new()
        {
            4624, 4625, 4648, 4672, 4663, 4698, 4699
        };

        /* ───── OpenTelemetry ───── */
        private static readonly ActivitySource Src = new("event.agent");
        private static readonly TracerProvider Otel =
            Sdk.CreateTracerProviderBuilder()
               .SetResourceBuilder(ResourceBuilder.CreateDefault()
                   .AddService("eventlog-agent"))
               .AddSource("event.agent")
               .AddOtlpExporter(o =>
               {
                   o.Endpoint = new("http://localhost:4319"); // Collector 주소
                   o.Protocol = OtlpExportProtocol.Grpc;
               })
               .Build();

        /* PID → 루트 Activity 매핑 */
        private static readonly ConcurrentDictionary<int, Activity> Roots = new();
        private static Activity? LastRoot; // PID를 못 찾았을 때 fallback

        private static void Main()
        {
            if (!(TraceEventSession.IsElevated() ?? false))
            {
                Console.WriteLine("[!] 관리자 권한으로 실행하세요.");
                return;
            }

            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine("[Agent] Sysmon(ETW) + Security(EventLog) 수집 시작  —  <Enter> 로 종료\n");

            /* ── 1. Sysmon ETW 세션 ── */
            using var sess = new TraceEventSession(EtwSessionName) { StopOnDispose = true };
            sess.EnableProvider(SysmonProvider, SysmonLevel, SysmonKeywords);
            sess.Source.AllEvents   += HandleSysmon;
            sess.Source.Dynamic.All += HandleSysmon;
            var etwThread = new Thread(() => sess.Source.Process()) { IsBackground = true };
            etwThread.Start();
            Console.WriteLine("[+] Sysmon ETW 세션 시작");

            /* ── 2. Security EventLogWatcher ── */
            using var secWatcher = StartSecurityWatcher();

            Console.ReadLine();

            /* ─ 종료 ─ */
            sess.Dispose();
            secWatcher.Enabled = false;
            Otel.Dispose();
            etwThread.Join();
        }

        /* ─────────────────────────────────────────── Sysmon ─ */
        private static void HandleSysmon(TraceEvent ev)
        {
            int pid = TryGetPayloadInt(ev, "ProcessId") ?? ev.ProcessID;
            int parentPid = TryGetPayloadInt(ev, "ParentProcessId") ?? 0;
            
            if (pid == 0) return; // Sysmon 이벤트는 PID 0 불가

            // // 루트 확보
            // var root = Roots.GetOrAdd(pid, _ => Src.StartActivity($"process:{pid}", ActivityKind.Internal)!);
            // LastRoot = root;

            // using var span = Src.StartActivity($"sysmon:{(int)ev.ID}", ActivityKind.Internal, parentContext: root.Context);
            // if (span == null) return;

            // Tag(span, "Channel", "Sysmon");
            // Tag(span, "EventId", (int)ev.ID);
            // Tag(span, "ProcessId", pid);
            if (!Roots.TryGetValue(pid, out var root))
            {
                root = Src.StartActivity($"process:{pid}", ActivityKind.Internal);
                if (root != null) Roots[pid] = root;
            }
            if (root == null) return;

            /* ③ 이벤트 단위 자식 Activity 생성 */
            using var child = Src.StartActivity($"evt:{(int)ev.ID}", ActivityKind.Internal,
                                                parentContext: root.Context);
            if (child == null) return;

            AddTags(child, ev, pid, parentPid);


            // Payload 태그 기록
            // if (ev.PayloadNames is { Length: > 0 })
            // {
            //     foreach (var n in ev.PayloadNames)
            //         Tag(span, n, ev.PayloadByName(n));
            // }

            Console.WriteLine($"[Sysmon] event {(int)ev.ID} : {pid}, {parentPid}");
        }

        /* ─────────────────────────────────────────── Security ─ */
        private static EventLogWatcher StartSecurityWatcher()
        {
            var query = new EventLogQuery("Security", PathType.LogName) { TolerateQueryErrors = true };
            var w = new EventLogWatcher(query, null, false);

            w.EventRecordWritten += (_, e) =>
            {
                if (e.EventRecord is null) return;
                if (!SecurityIds.Contains(e.EventRecord.Id)) { e.EventRecord.Dispose(); return; }
                HandleSecurity(e.EventRecord);
            };
            w.Enabled = true;
            Console.WriteLine("[+] Security EventLogWatcher 활성화");
            return w;
        }

        private static void HandleSecurity(EventRecord rec)
        {
            using (rec)
            {
                int pid = rec.ProcessId ?? 0;

                // 부모 루트 찾기: 동일 PID 있으면, 없으면 최근 Sysmon Root fallback
                Roots.TryGetValue(pid, out var parent);
                parent ??= LastRoot;

                using var span = Src.StartActivity($"security:{rec.Id}", ActivityKind.Internal,
                    parentContext: parent?.Context ?? default);
                if (span == null) return;

                if (parent is null && pid != 0) Roots[pid] = span; // 첫 Security가 루트가 될 때

                Tag(span, "Channel", "Security");
                Tag(span, "EventId", rec.Id);
                Tag(span, "RecordId", rec.RecordId);
                Tag(span, "ProcessId", pid);
                Tag(span, "TimeCreated", rec.TimeCreated);

                for (int i = 0; i < rec.Properties.Count; i++)
                    Tag(span, $"Data{i}", rec.Properties[i].Value);

                Console.WriteLine($"[Security] event {rec.Id} : {pid}");
            }
        }

        /* ─────────────────────────────────────────── Helpers ─ */
        private static void Tag(Activity span, string k, object? v)
        {
            if (v is null) return;
            span.SetTag(k, v);
        }
        
        private static void AddTags(Activity act, TraceEvent ev, int pid, int ppid)
        {
            void T(string k, object? v) { if (v != null) act.SetTag(k, v); }

            /* 기본 태그 */
            T("sysmon.pid", pid);
            if (ppid != 0) T("sysmon.ppid", ppid);
            T("sysmon.event_id", (int)ev.ID);
            T("sysmon.task", ev.Task);
            T("sysmon.opcode", ev.Opcode);
            T("provider_guid", ev.ProviderGuid);

            /* TraceEvent의 public 속성 전체 태그화 */
            foreach (var p in ev.GetType()
                                .GetProperties(BindingFlags.Public | BindingFlags.Instance)
                                .Where(p => p.GetIndexParameters().Length == 0))
            {
                try { T(p.Name, p.GetValue(ev)); } catch { }
            }

            /* Payload 필드 태그화 */
            if (ev.PayloadNames is { Length: > 0 })
            {
                foreach (var n in ev.PayloadNames)
                {
                    try { T(n, ev.PayloadByName(n)); } catch { }
                }
            }
        }
        private static int? TryGetPayloadInt(TraceEvent ev, string field)
        {
            if (ev.PayloadNames?.Contains(field) == true)
            {
                try
                {
                    object? val = ev.PayloadByName(field);
                    return val switch
                    {
                        int i => i,
                        long l => (int)l,
                        string s when int.TryParse(s, out int parsed) => parsed,
                        _ => null
                    };
                }
                catch { /* ignore */ }
            }
            return null;
        }
    }
}
