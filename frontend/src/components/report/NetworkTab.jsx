import { useState } from "react";
import { Copy, AlertTriangle } from "lucide-react";

export default function NetworkTab({ dynamicResult, cloud }) {
  const artifacts = dynamicResult?.network_artifacts || [];
  const ja4Hashes = dynamicResult?.ja4_hashes || [];

  return (
    <div className="space-y-8">
      {ja4Hashes.length > 0 && (
        <div>
          <h3 className="mb-3 font-mono text-xs uppercase tracking-widest text-muted">JA4 Fingerprints</h3>
          <div className="space-y-2">
            {[...new Set(ja4Hashes)].map((h) => (
              <CopyableHash key={h} value={h} />
            ))}
          </div>
        </div>
      )}

      <div>
        <h3 className="mb-3 font-mono text-xs uppercase tracking-widest text-muted">
          Network Artifacts ({artifacts.length})
        </h3>
        <table className="data-table w-full">
          <thead>
            <tr>
              <th>URL</th>
              <th>Method</th>
              <th>Host</th>
              <th>Interceptor</th>
            </tr>
          </thead>
          <tbody>
            {artifacts.map((a, i) => (
              <tr key={i}>
                <td className="break-all">{a.url}</td>
                <td>{a.method}</td>
                <td>{a.host}</td>
                <td className="text-amber">{a.interceptor_class || "—"}</td>
              </tr>
            ))}
            {artifacts.length === 0 && (
              <tr>
                <td colSpan={4} className="text-muted">No network artifacts captured.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {cloud && (
        <div className="space-y-2">
          {cloud.domain_fronting?.length > 0 && (
            <AlertBanner text={`Domain fronting detected on ${cloud.domain_fronting.length} host(s)`} />
          )}
          {cloud.dga_domains?.length > 0 && (
            <AlertBanner text={`DGA-pattern domains detected: ${cloud.dga_domains.map((d) => d.domain).join(", ")}`} />
          )}
          {cloud.tunnel_services?.length > 0 && (
            <AlertBanner
              text={`Tunnel service detected: ${cloud.tunnel_services.map((t) => `${t.domain} (${t.service})`).join(", ")}`}
            />
          )}
        </div>
      )}
    </div>
  );
}

function AlertBanner({ text }) {
  return (
    <div className="flex items-center gap-2 border border-alarm/50 bg-alarm/5 p-3 font-mono text-xs text-alarm">
      <AlertTriangle size={14} className="shrink-0" /> {text}
    </div>
  );
}

function CopyableHash({ value }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="panel flex items-center justify-between p-3">
      <span className="break-all font-mono text-xs text-cyan">{value}</span>
      <button
        onClick={() => {
          navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        }}
        className="ml-3 shrink-0 text-muted hover:text-ink"
      >
        <Copy size={14} className={copied ? "text-neon" : ""} />
      </button>
    </div>
  );
}
