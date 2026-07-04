import { Fingerprint, ShieldAlert, MapPin } from "lucide-react";
import StatCard from "../common/StatCard.jsx";
import SandboxVisualizer from "./SandboxVisualizer.jsx";

// Real, documented per-stage RAM budgets from backend/config.py's design
// (static ~0.8GB, dynamic AVD ~4GB, LLM narrative ~5GB) — there is no live
// per-second RAM telemetry endpoint, so this shows the *budgeted* ceiling
// for whichever stage is active rather than fabricating a live reading.
const STAGE_BUDGET_MB = {
  STATIC_TRIAGE: 800,
  DYNAMIC_ANALYSIS: 4096,
  CLOUD_C2_DETECTION: 300,
  NEO4J_GRAPH: 1024,
  LLM_NARRATIVE: 5120,
  PDF_GENERATION: 300,
  JARM_PROBE: 200,
};
const TOTAL_BUDGET_MB = 16000;

export default function MetricsPanel({ iocCount, yaraMatchCount, indiaMatchCount, currentStage, apkMeta }) {
  const budget = STAGE_BUDGET_MB[currentStage] || 0;
  const pct = Math.min(100, Math.round((budget / TOTAL_BUDGET_MB) * 100));

  return (
    <div className="flex h-full flex-col gap-3">
      <div className="grid grid-cols-1 gap-2">
        <StatCard label="IOCs Extracted" value={iocCount} accent="cyan" icon={MapPin} />
        <StatCard label="YARA Matches" value={yaraMatchCount} accent="crimson" icon={ShieldAlert} />
        <StatCard label="India Patterns" value={indiaMatchCount} accent="amber" icon={Fingerprint} />
      </div>

      <div className="panel p-3">
        <div className="mb-1 flex justify-between font-mono text-[10px] text-muted">
          <span>STAGE RAM BUDGET ({currentStage || "—"})</span>
          <span>{budget ? `${(budget / 1024).toFixed(1)}GB / 16GB` : "—"}</span>
        </div>
        <div className="h-2 w-full bg-border">
          <div
            className={`h-full transition-all duration-700 ${
              pct > 70 ? "bg-alarm" : pct > 40 ? "bg-amber" : "bg-neon"
            }`}
            style={{ width: `${pct}%` }}
          />
        </div>
      </div>

      <div className="min-h-0 flex-1">
        <SandboxVisualizer apkMeta={apkMeta} active={currentStage === "DYNAMIC_ANALYSIS"} />
      </div>
    </div>
  );
}
