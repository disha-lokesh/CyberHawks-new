import { useParams, useNavigate } from "react-router-dom";
import { useEffect } from "react";
import { useAnalysisStream } from "../lib/useAnalysisStream.js";
import { useStore } from "../lib/store.js";
import PipelineStages from "../components/analysis/PipelineStages.jsx";
import RadialGauge from "../components/common/RadialGauge.jsx";
import StageFeed from "../components/analysis/StageFeed.jsx";
import MetricsPanel from "../components/analysis/MetricsPanel.jsx";

export default function Analysis() {
  const { id } = useParams();
  const navigate = useNavigate();
  const setAnalysisId = useStore((s) => s.setAnalysisId);

  const currentStage = useStore((s) => s.currentStage);
  const riskScore = useStore((s) => s.riskScore);
  const riskTier = useStore((s) => s.riskTier);
  const stages = useStore((s) => s.stages);
  const iocCount = useStore((s) => s.iocCount);
  const yaraMatchCount = useStore((s) => s.yaraMatchCount);
  const indiaMatchCount = useStore((s) => s.indiaMatchCount);
  const terminalLines = useStore((s) => s.terminalLines);
  const apkMeta = useStore((s) => s.apkMeta);

  useEffect(() => {
    setAnalysisId(id);
  }, [id, setAnalysisId]);

  useAnalysisStream(id);

  useEffect(() => {
    if (currentStage === "COMPLETE") {
      const t = setTimeout(() => navigate(`/report/${id}`), 1200);
      return () => clearTimeout(t);
    }
  }, [currentStage, id, navigate]);

  const isCritical = riskTier === "CRITICAL";

  return (
    <div
      className={`grid h-[calc(100vh-52px)] grid-cols-[260px_1fr_320px] gap-px bg-border transition-shadow ${
        isCritical ? "animate-pulseBorder ring-2 ring-alarm" : ""
      }`}
    >
      <aside className="overflow-y-auto bg-bg p-3">
        <h3 className="mb-3 font-mono text-[10px] uppercase tracking-widest text-muted">
          Pipeline Stages
        </h3>
        <PipelineStages stages={stages} currentStage={currentStage} />
      </aside>

      <main className="flex flex-col gap-3 overflow-hidden bg-bg p-4">
        <div className="panel flex items-center justify-center py-6">
          <RadialGauge score={riskScore ?? 0} tier={riskTier} />
        </div>
        <div className="min-h-0 flex-1">
          <StageFeed lines={terminalLines} />
        </div>
      </main>

      <aside className="overflow-y-auto bg-bg p-3">
        <MetricsPanel
          iocCount={iocCount}
          yaraMatchCount={yaraMatchCount}
          indiaMatchCount={indiaMatchCount}
          currentStage={currentStage}
          apkMeta={apkMeta}
        />
      </aside>
    </div>
  );
}
