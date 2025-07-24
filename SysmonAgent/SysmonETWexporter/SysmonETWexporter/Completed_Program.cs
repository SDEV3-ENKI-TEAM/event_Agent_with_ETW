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
using System.Reflection;
using System.Linq;
using System.Threading;

namespace EventLogUnifiedAgent
{
    internal class Program
    {
        /* ───── ETW 공급자 설정 ───── */
        private const string SysmonProvider   = "Microsoft-Windows-Sysmon";
        private const string SecurityProvider = "Microsoft-Windows-Security-Auditing";
        private const ulong  AllKeywords      = ulong.MaxValue;
        private const TraceEventLevel Level   = TraceEventLevel.Informational;
        private const string SessionName      = "EventAgent_ETW";

        /* ───── OpenTelemetry ───── */
        private static readonly ActivitySource Src = new("event.agent");
        private static readonly TracerProvider Otel =
            Sdk.CreateTracerProviderBuilder()
               .SetResourceBuilder(ResourceBuilder.CreateDefault()
                               .AddService("eventlog-agent"))
               .AddSource("event.agent")
               .AddOtlpExporter(o =>
               {
                   o.Endpoint = new Uri("http://localhost:4319");   // ▶ Collector 주소
                   o.Protocol = OtlpExportProtocol.Grpc;
               })
               .Build();

        /* PID → 루트 Activity 맵 */
        private static readonly ConcurrentDictionary<int, Activity> Roots = new();

        /* ───── Entry ───── */
        private static void Main()
        {
            if (!(TraceEventSession.IsElevated() ?? false))
            {
                Console.WriteLine("[!] 관리자 권한으로 다시 실행하세요.");
                return;
            }

            Console.WriteLine("Sysmon + Security-Auditing ETW 수집 시작 …   <Enter> 로 종료\n");

            using var sess = new TraceEventSession(SessionName) { StopOnDispose = true };

            /* 1. 공급자 등록 */
            sess.EnableProvider(SysmonProvider,   Level, AllKeywords);
            sess.EnableProvider(SecurityProvider, Level, AllKeywords);

            /* 2. 콜백 등록 */
            sess.Source.AllEvents   += HandleEvent;
            sess.Source.Dynamic.All += HandleEvent;

            /* 3. ETW 처리 스레드 */
            var etwThread = new Thread(() => sess.Source.Process()) { IsBackground = true };
            etwThread.Start();

            Console.ReadLine();

            /* ─ Clean up ─ */
            sess.Dispose();
            Otel.Dispose();
            etwThread.Join();
        }
    
    // ─────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────
    private static int? GetInt(TraceEvent e, string field)
    {
        if (e.PayloadNames?.Contains(field) == true)
        {
            try
            {
                object? v = e.PayloadByName(field);
                return v switch
                {
                    int i                                      => i,
                    long l                                     => (int)l,
                    string s when int.TryParse(s, out int p)   => p,
                    _                                          => null
                };
            }
            catch { /* ignore */ }
        }
        return null;
    }

        /* ─────────────────────────────────────────────────────────────── */
    private static void HandleEvent(TraceEvent ev)
    {
      /* 공급자 구분 */
      string channel = ev.ProviderName switch
      {
        "Microsoft-Windows-Sysmon" => "Sysmon",
        "Microsoft-Windows-Security-Auditing" => "Security",
        _ => "Other"
      };

      /* 관심 없는 공급자라면 return */
      if (channel == "Other") return;

      int pid = ev.ProcessID;
      int ppid = GetInt(ev, "ParentProcessId") ?? 0;

      /* ─ 루트 Activity 확보 ─ */
      if (!Roots.TryGetValue(pid, out var root))
      {
        root = Src.StartActivity($"process:{pid}", ActivityKind.Internal);
        if (root != null) Roots[pid] = root;
      }
      if (root is null) return;

      /* ─ Child span 생성 ─ */
      using var span = Src.StartActivity(
          $"{channel.ToLower()}:{(int)ev.ID}",
          ActivityKind.Internal,
          parentContext: root.Context);

      if (span == null) return;

      /* ─ 태그 기록 ─ */
      void T(string k, object? v) { if (v != null) span.SetTag(k, v); }

      T("Channel", channel);
      T("EventId", (int)ev.ID);
      T("ProcessId", pid);
      T("ParentProcessId", ppid);
      T("ProviderGuid", ev.ProviderGuid);
      T("Task", ev.Task);
      T("Opcode", ev.Opcode);
      T("TimeCreated", ev.TimeStamp);

      /* 모든 Payload 필드 태그화 */
      if (ev.PayloadNames is { Length: > 0 })
      {
        foreach (var n in ev.PayloadNames)
        {
          try { T(n, ev.PayloadByName(n)); } catch { }
        }
      }

      /* ─ 디버그 출력 ─ */
      Console.WriteLine($"[{channel}] 감사{(int)ev.ID} : {pid}");
    }
    }
}
