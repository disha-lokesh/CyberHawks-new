import { useState } from "react";
import { CheckCircle2, ChevronDown, Skull } from "lucide-react";
import { RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, ResponsiveContainer } from "recharts";
import AnimatedNumber from "../common/AnimatedNumber.jsx";

const HOOK_LABELS = {
  network: "Network Hooks", crypto: "Crypto Key Extraction", sms: "SMS Hooks",
  interceptor: "OkHttp Interceptor Attribution", clipboard: "Clipboard Hooks",
  accessibility: "Accessibility Hooks", permission: "Permission Request Hooks",
};

export default function DynamicTab({ dynamicResult }) {
  if (!dynamicResult) {
    return (
      <div className="font-mono text-xs text-muted">
        Dynamic analysis did not run for this APK (risk score stayed below the HIGH_RISK escalation threshold).
      </div>
    );
  }

  const { anti_evasion, monkeyrunner_stats, syscall_profile, frida_artifacts, memory_dump_scan } = dynamicResult;
  const radarData = Object.entries(syscall_profile?.freq || {}).map(([syscall, count]) => ({ syscall, count }));
  const memoryHits = (memory_dump_scan?.yara_matches?.length || 0) + (memory_dump_scan?.india_matches?.length || 0);

  return (
    <div className="space-y-8">
      {memory_dump_scan && memoryHits > 0 && (
        <div className="border border-alarm/60 bg-alarm/5 p-4">
          <h3 className="mb-2 flex items-center gap-2 font-mono text-xs uppercase tracking-widest text-alarm">
            <Skull size={14} /> Runtime Memory Dump — Decrypted Payload Caught
          </h3>
          <p className="mb-3 font-mono text-[10px] text-muted">
            {memory_dump_scan.dump_size_bytes.toLocaleString()} bytes captured mid-execution and
            re-scanned through the same YARA/India-pattern engines used on the static APK —
            {memoryHits} match(es) found here that static analysis never saw on disk.
          </p>
          <div className="space-y-1">
            {memory_dump_scan.yara_matches.map((m, i) => (
              <div key={`y${i}`} className="font-mono text-[11px] text-ink">
                <span className="text-crimson">{m.rule_name}</span> ({m.category}):{" "}
                {m.strings_matched.slice(0, 3).join(", ")}
              </div>
            ))}
            {memory_dump_scan.india_matches.map((m, i) => (
              <div key={`i${i}`} className="font-mono text-[11px] text-ink">
                <span className="text-amber">{m.pattern_name}</span> ({m.category}):{" "}
                {m.matched_strings.slice(0, 3).join(", ")}
              </div>
            ))}
          </div>
        </div>
      )}

      <div>
        <h3 className="mb-3 font-mono text-xs uppercase tracking-widest text-muted">
          Anti-Evasion Steps ({anti_evasion?.steps_applied?.length || 0})
        </h3>
        <div className="grid grid-cols-2 gap-2">
          {(anti_evasion?.steps_applied || []).map((s, i) => (
            <div key={i} className="flex items-center gap-2 font-mono text-xs text-ink">
              <CheckCircle2 size={13} className="shrink-0 text-neon" /> {s}
            </div>
          ))}
        </div>
      </div>

      {monkeyrunner_stats && (
        <div className="grid grid-cols-4 gap-3">
          {["taps", "swipes", "text_inputs", "keypresses"].map((k) => (
            <div key={k} className="panel p-3 text-center">
              <div className="font-mono text-2xl font-bold tabular-nums text-cyan">
                <AnimatedNumber value={monkeyrunner_stats[k] || 0} />
              </div>
              <div className="font-mono text-[10px] uppercase text-muted">{k.replace("_", " ")}</div>
            </div>
          ))}
        </div>
      )}

      {radarData.length > 0 && (
        <div>
          <h3 className="mb-3 font-mono text-xs uppercase tracking-widest text-muted">
            Syscall Frequency ({syscall_profile.total_calls} total calls)
          </h3>
          <div className="panel h-72 p-4">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={radarData}>
                <PolarGrid stroke="#1a1a2e" />
                <PolarAngleAxis dataKey="syscall" tick={{ fill: "#6b6b8a", fontSize: 10 }} />
                <PolarRadiusAxis tick={{ fill: "#6b6b8a", fontSize: 9 }} />
                <Radar dataKey="count" stroke="#00d4ff" fill="#00d4ff" fillOpacity={0.35} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      <div>
        <h3 className="mb-3 font-mono text-xs uppercase tracking-widest text-muted">Frida Hook Results</h3>
        <div className="space-y-2">
          {Object.entries(frida_artifacts || {}).map(([bucket, events]) => (
            <HookCard key={bucket} label={HOOK_LABELS[bucket] || bucket} events={events} />
          ))}
        </div>
      </div>
    </div>
  );
}

function HookCard({ label, events }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="panel">
      <button onClick={() => setOpen((o) => !o)} className="flex w-full items-center justify-between p-3 font-mono text-xs">
        <span className="text-ink">{label}</span>
        <span className="flex items-center gap-2 text-muted">
          {events.length} events
          <ChevronDown size={13} className={`transition-transform ${open ? "rotate-180" : ""}`} />
        </span>
      </button>
      {open && (
        <div className="max-h-48 overflow-y-auto border-t border-border p-3 font-mono text-[10px] text-muted">
          {events.length === 0 && <div>No events captured.</div>}
          {events.map((e, i) => (
            <pre key={i} className="mb-1 whitespace-pre-wrap break-all">{JSON.stringify(e)}</pre>
          ))}
        </div>
      )}
    </div>
  );
}
