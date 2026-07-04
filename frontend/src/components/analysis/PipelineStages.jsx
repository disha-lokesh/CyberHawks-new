import { motion } from "framer-motion";
import { CheckCircle2, XCircle, Circle, Loader2 } from "lucide-react";
import { PIPELINE_STAGES } from "../../lib/store.js";

const LABELS = {
  STATIC_TRIAGE: "STATIC TRIAGE",
  DYNAMIC_ANALYSIS: "DYNAMIC ANALYSIS",
  CLOUD_C2_DETECTION: "CLOUD C2",
  NEO4J_GRAPH: "NEO4J GRAPH",
  LLM_NARRATIVE: "LLM NARRATIVE",
  PDF_GENERATION: "PDF GENERATION",
  JARM_PROBE: "JARM PROBE",
};

export default function PipelineStages({ stages, currentStage }) {
  return (
    <div className="flex flex-col gap-1">
      {PIPELINE_STAGES.map((name) => {
        const sr = stages[name];
        const status = sr?.status || (currentStage === name ? "running" : "pending");
        const isActive = currentStage === name;
        return (
          <motion.div
            key={name}
            animate={isActive ? { boxShadow: ["0 0 0px #00d4ff00", "0 0 14px #00d4ff88", "0 0 0px #00d4ff00"] } : {}}
            transition={{ duration: 1.2 }}
            className={`flex items-center gap-3 border-l-2 px-3 py-2.5 ${
              status === "done"
                ? "border-neon"
                : status === "failed"
                ? "border-alarm"
                : isActive
                ? "border-cyan"
                : "border-border"
            }`}
          >
            <StatusIcon status={status} />
            <div className="flex-1">
              <div
                className={`font-mono text-xs ${
                  status === "pending" ? "text-muted" : "text-ink"
                }`}
              >
                {LABELS[name]}
              </div>
              <div className="mt-1 h-0.5 w-full bg-border">
                <div
                  className={`h-full transition-all duration-700 ${
                    status === "done" ? "bg-neon w-full" : status === "failed" ? "bg-alarm w-full" : isActive ? "bg-cyan w-2/3" : "w-0"
                  }`}
                />
              </div>
            </div>
            <span className="font-mono text-[10px] tabular-nums text-muted">
              {sr?.duration_seconds ? `${sr.duration_seconds.toFixed(1)}s` : ""}
            </span>
          </motion.div>
        );
      })}
    </div>
  );
}

function StatusIcon({ status }) {
  if (status === "done") return <CheckCircle2 size={16} className="shrink-0 text-neon" />;
  if (status === "failed") return <XCircle size={16} className="shrink-0 text-alarm" />;
  if (status === "running") return <Loader2 size={16} className="shrink-0 animate-spin text-cyan" />;
  return <Circle size={16} className="shrink-0 text-border" />;
}
