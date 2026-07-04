import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { listAnalyses } from "../lib/api.js";
import { SkeletonPage } from "../components/common/Skeleton.jsx";

const TIER_COLOR = {
  BENIGN: "#00ff88",
  SUSPICIOUS: "#f39c12",
  HIGH_RISK: "#e67e22",
  CRITICAL: "#ff2244",
};

export default function History() {
  const [analyses, setAnalyses] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    listAnalyses()
      .then((r) => !cancelled && setAnalyses(r.data.analyses))
      .catch(() => !cancelled && setError("Could not reach backend."));
    return () => {
      cancelled = true;
    };
  }, []);

  if (error) return <div className="p-10 font-mono text-sm text-alarm">{error}</div>;
  if (!analyses) return <SkeletonPage />;

  return (
    <div className="p-8">
      <h1 className="mb-1 text-2xl font-semibold text-ink">Analysis History</h1>
      <p className="mb-6 font-mono text-xs text-muted">
        All analyses run against this backend process — {analyses.length} total.
      </p>

      {analyses.length === 0 ? (
        <div className="panel p-8 text-center font-mono text-sm text-muted">
          No analyses yet. Upload an APK to get started.
        </div>
      ) : (
        <table className="data-table w-full">
          <thead>
            <tr>
              <th>Started</th>
              <th>FIR Number</th>
              <th>APK</th>
              <th>Stage</th>
              <th>Risk Score</th>
              <th>Tier</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {analyses.map((a) => (
              <tr key={a.analysis_id}>
                <td className="font-mono text-xs">
                  {a.started_at ? new Date(a.started_at).toLocaleString() : "--"}
                </td>
                <td className="font-mono text-xs">{a.fir_number || "--"}</td>
                <td className="max-w-[220px] truncate font-mono text-xs" title={a.apk_filename}>
                  {a.apk_filename || "--"}
                </td>
                <td className="font-mono text-xs">
                  {a.current_stage}
                  {a.error && (
                    <span className="ml-1 text-alarm" title={a.error}>
                      ⚠
                    </span>
                  )}
                </td>
                <td className="font-mono text-xs tabular-nums">
                  {a.risk_score?.toFixed?.(1) ?? "--"}
                </td>
                <td
                  className="font-mono text-xs tracking-widest"
                  style={{ color: TIER_COLOR[a.risk_tier] || "#6b6b8a" }}
                >
                  {a.risk_tier || "--"}
                </td>
                <td>
                  {a.current_stage === "COMPLETE" ? (
                    <Link to={`/report/${a.analysis_id}`} className="font-mono text-xs text-cyan hover:underline">
                      View Report →
                    </Link>
                  ) : a.current_stage === "FAILED" ? (
                    <span className="font-mono text-xs text-muted">Failed</span>
                  ) : (
                    <Link to={`/analysis/${a.analysis_id}`} className="font-mono text-xs text-amber hover:underline">
                      In Progress →
                    </Link>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
