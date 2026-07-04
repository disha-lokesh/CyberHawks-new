import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Download } from "lucide-react";
import { getResult, getStaticResult, getDynamicResult, reportDownloadUrl } from "../lib/api.js";
import { SkeletonPage } from "../components/common/Skeleton.jsx";
import OverviewTab from "../components/report/OverviewTab.jsx";
import PermissionsTab from "../components/report/PermissionsTab.jsx";
import CodeAnalysisTab from "../components/report/CodeAnalysisTab.jsx";
import DynamicTab from "../components/report/DynamicTab.jsx";
import NetworkTab from "../components/report/NetworkTab.jsx";
import IocsTab from "../components/report/IocsTab.jsx";
import ShapTab from "../components/report/ShapTab.jsx";

const TABS = ["Overview", "Permissions", "Code Analysis", "Dynamic", "Network", "IOCs", "SHAP"];

const TIER_GRADIENT = {
  BENIGN: "from-tier-benign/20",
  SUSPICIOUS: "from-tier-suspicious/20",
  HIGH_RISK: "from-tier-high/20",
  CRITICAL: "from-tier-critical/25",
};

export default function Report() {
  const { id } = useParams();
  const [result, setResult] = useState(null);
  const [staticResult, setStaticResult] = useState(null);
  const [dynamicResult, setDynamicResult] = useState(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState("Overview");

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      const [resultRes, staticRes, dynamicRes] = await Promise.allSettled([
        getResult(id),
        getStaticResult(id),
        getDynamicResult(id),
      ]);
      if (cancelled) return;
      if (resultRes.status === "fulfilled") setResult(resultRes.value.data);
      if (staticRes.status === "fulfilled") setStaticResult(staticRes.value.data);
      if (dynamicRes.status === "fulfilled") setDynamicResult(dynamicRes.value.data);
      setLoading(false);
    }
    load();
    return () => {
      cancelled = true;
    };
  }, [id]);

  if (loading) return <SkeletonPage />;
  if (!result) return <div className="p-10 font-mono text-sm text-muted">Analysis not found.</div>;

  const tier = result.risk_tier || "SUSPICIOUS";
  const pkg = staticResult?.manifest?.package_name || "unknown.package";

  return (
    <div>
      <div className={`relative overflow-hidden bg-gradient-to-b ${TIER_GRADIENT[tier]} to-bg border-b border-border px-8 py-10`}>
        <div className="font-mono text-xs uppercase tracking-widest text-muted">Forensic Report</div>
        <div className="mt-2 flex items-end justify-between">
          <div>
            <div className="text-2xl font-semibold text-ink">{pkg}</div>
            <div className="mt-1 break-all font-mono text-xs text-muted">
              {staticResult?.apk_sha256}
            </div>
          </div>
          <div className="text-right">
            <div className="font-mono text-4xl font-bold tabular-nums" style={{ color: tierColor(tier) }}>
              {result.risk_score?.toFixed?.(1) ?? "--"}
            </div>
            <div className="font-mono text-xs tracking-widest" style={{ color: tierColor(tier) }}>
              {tier}
            </div>
          </div>
        </div>
      </div>

      <nav className="flex gap-6 border-b border-border px-8 font-mono text-xs">
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`relative py-3 uppercase tracking-wider transition-colors ${
              tab === t ? "text-crimson" : "text-muted hover:text-ink"
            }`}
          >
            {t}
            {tab === t && (
              <motion.div layoutId="tab-underline" className="absolute inset-x-0 -bottom-px h-0.5 bg-crimson" />
            )}
          </button>
        ))}
      </nav>

      <div className="p-8">
        {tab === "Overview" && <OverviewTab staticResult={staticResult} result={result} />}
        {tab === "Permissions" && <PermissionsTab staticResult={staticResult} />}
        {tab === "Code Analysis" && <CodeAnalysisTab staticResult={staticResult} />}
        {tab === "Dynamic" && <DynamicTab dynamicResult={dynamicResult} />}
        {tab === "Network" && (
          <NetworkTab dynamicResult={dynamicResult} staticResult={staticResult} cloud={result.results?.cloud} />
        )}
        {tab === "IOCs" && <IocsTab staticResult={staticResult} dynamicResult={dynamicResult} />}
        {tab === "SHAP" && <ShapTab riskScore={staticResult?.risk_score} />}
      </div>

      {result.results?.llm?.text && (
        <div className="border-t border-border p-8">
          <h3 className="mb-3 font-mono text-xs uppercase tracking-widest text-muted">
            Forensic Narrative
          </h3>
          <div className="panel p-6 font-serif text-sm leading-relaxed text-ink/90">
            {result.results.llm.text}
          </div>
        </div>
      )}

      <div className="flex justify-center border-t border-border p-8">
        <a
          href={reportDownloadUrl(id)}
          className="flex items-center gap-2 border border-crimson px-8 py-3 font-mono text-sm tracking-widest text-crimson transition hover:bg-crimson hover:text-black"
        >
          <Download size={16} /> DOWNLOAD SIGNED PDF
        </a>
      </div>
    </div>
  );
}

function tierColor(tier) {
  return { BENIGN: "#00ff88", SUSPICIOUS: "#f39c12", HIGH_RISK: "#e67e22", CRITICAL: "#ff2244" }[tier] || "#6b6b8a";
}
