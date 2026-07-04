import { useState } from "react";
import { Check, X, Search, KeyRound, ShieldAlert, Layers, ScanSearch, Cpu } from "lucide-react";

export default function CodeAnalysisTab({ staticResult }) {
  const dex = staticResult?.dex;
  const jadx = staticResult?.jadx;
  const config = staticResult?.config;
  const dependencies = staticResult?.dependencies;
  const mobsf = staticResult?.mobsf;
  const ghidra = staticResult?.ghidra;
  const [query, setQuery] = useState("");
  const [sortDesc, setSortDesc] = useState(true);

  const rows = dex
    ? [
        ...dex.urls.map((v) => ({ type: "URL", value: v })),
        ...dex.ips.map((v) => ({ type: "IP", value: v })),
      ].filter((r) => r.value.toLowerCase().includes(query.toLowerCase()))
    : [];
  if (!sortDesc) rows.reverse();

  const hasCodeReview = jadx?.available || mobsf?.available || ghidra?.so_files_analyzed?.length > 0 || (config && config.anomalies?.length) || (dependencies && (dependencies.ad_sdks_detected?.length || dependencies.analytics_sdks_detected?.length));

  return (
    <div className="space-y-8">
      {!dex && (
        <div className="font-mono text-xs text-muted">DEX analysis unavailable.</div>
      )}

      {dex && (
        <>
          <div>
            <h3 className="mb-3 font-mono text-xs uppercase tracking-widest text-muted">
              Obfuscation Level
            </h3>
            <div className="flex gap-1">
              {[0, 1, 2, 3].map((i) => (
                <div
                  key={i}
                  className={`h-6 flex-1 ${i < dex.obfuscation_level ? "bg-crimson" : "bg-border"}`}
                />
              ))}
            </div>
            <div className="mt-2 space-y-1 font-mono text-[10px] text-muted">
              {dex.obfuscation_evidence.map((e, i) => (
                <div key={i}>• {e}</div>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <BoolCard label="Reflection API Used" value={dex.reflection_used} />
            <BoolCard label="Dynamic DEX Loading" value={dex.dynamic_loading} />
          </div>

          <div className="grid grid-cols-4 gap-3 font-mono text-xs">
            <Stat label="Classes" value={dex.class_count} />
            <Stat label="Methods" value={dex.method_count} />
            <Stat label="Crypto Classes" value={dex.crypto_classes.length} />
            <Stat label="Network Classes" value={dex.network_classes.length} />
          </div>

          <div>
            <div className="mb-3 flex items-center justify-between">
              <h3 className="font-mono text-xs uppercase tracking-widest text-muted">
                Extracted URLs & IPs ({rows.length})
              </h3>
              <div className="flex items-center gap-2 border-b border-border px-2 py-1">
                <Search size={12} className="text-muted" />
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="filter…"
                  className="bg-transparent font-mono text-xs outline-none"
                />
              </div>
            </div>
            <table className="data-table w-full">
              <thead>
                <tr>
                  <th>Type</th>
                  <th className="cursor-pointer" onClick={() => setSortDesc((s) => !s)}>
                    Value {sortDesc ? "▼" : "▲"}
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r, i) => (
                  <tr key={i}>
                    <td>{r.type}</td>
                    <td className="break-all">{r.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {dex.encoded_payloads.length > 0 && (
            <div>
              <h3 className="mb-3 font-mono text-xs uppercase tracking-widest text-muted">
                Encoded Payload Blobs
              </h3>
              <div className="space-y-1">
                {dex.encoded_payloads.map((p, i) => (
                  <div key={i} className="break-all border border-amber/40 bg-amber/5 p-2 font-mono text-[10px] text-amber">
                    {p.slice(0, 120)}…
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {jadx && (
        <div>
          <h3 className="mb-3 flex items-center gap-2 font-mono text-xs uppercase tracking-widest text-muted">
            <KeyRound size={12} /> Source-Level SAST (JADX)
          </h3>
          {!jadx.available ? (
            <div className="font-mono text-[10px] text-muted">
              {jadx.errors?.[0] || "jadx decompilation unavailable."}
            </div>
          ) : (
            <>
              <div className="mb-3 grid grid-cols-4 gap-3 font-mono text-xs">
                <Stat label="Files Scanned" value={jadx.files_scanned} />
                <Stat label="Hardcoded IPs" value={jadx.hardcoded_ips.length} />
                <Stat label="Hardcoded URLs" value={jadx.hardcoded_urls.length} />
                <Stat label="Secrets Found" value={jadx.secrets_found.length} />
              </div>
              {jadx.secrets_found.length > 0 && (
                <table className="data-table w-full">
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>File</th>
                      <th>Preview</th>
                    </tr>
                  </thead>
                  <tbody>
                    {jadx.secrets_found.map((s, i) => (
                      <tr key={i}>
                        <td>{s.type}</td>
                        <td className="break-all">{s.file}</td>
                        <td className="break-all">{s.match_preview}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              {jadx.suspicious_routes.length > 0 && (
                <div className="mt-2 space-y-1 font-mono text-[10px] text-muted">
                  {jadx.suspicious_routes.slice(0, 20).map((r, i) => (
                    <div key={i}>• {r}</div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}

      {config && (config.anomalies?.length > 0 || config.network_security_config_present) && (
        <div>
          <h3 className="mb-3 flex items-center gap-2 font-mono text-xs uppercase tracking-widest text-muted">
            <ShieldAlert size={12} /> Configuration Analysis
          </h3>
          <div className="grid grid-cols-2 gap-4">
            <BoolCard label="Cleartext Traffic Permitted" value={config.cleartext_permitted_globally || config.cleartext_permitted_domains.length > 0} />
            <BoolCard label="Trusts User-Installed CAs" value={config.trusts_user_added_cas} />
          </div>
          <div className="mt-2 space-y-1 font-mono text-[10px] text-muted">
            {config.anomalies.map((a, i) => (
              <div key={i}>• {a}</div>
            ))}
          </div>
        </div>
      )}

      {dependencies && (dependencies.ad_sdks_detected?.length > 0 || dependencies.analytics_sdks_detected?.length > 0) && (
        <div>
          <h3 className="mb-3 flex items-center gap-2 font-mono text-xs uppercase tracking-widest text-muted">
            <Layers size={12} /> Third-Party SDKs
          </h3>
          {dependencies.ad_sdks_detected.length > 0 && (
            <div className="mb-1 font-mono text-xs text-ink">
              Ad-mediation: {dependencies.ad_sdks_detected.join(", ")}
            </div>
          )}
          {dependencies.analytics_sdks_detected.length > 0 && (
            <div className="mb-1 font-mono text-xs text-ink">
              Analytics: {dependencies.analytics_sdks_detected.join(", ")}
            </div>
          )}
          <div className="mt-2 space-y-1 font-mono text-[10px] text-amber">
            {dependencies.anomalies.map((a, i) => (
              <div key={i}>• {a}</div>
            ))}
          </div>
        </div>
      )}

      {ghidra?.so_files_analyzed?.length > 0 && (
        <div>
          <h3 className="mb-3 flex items-center gap-2 font-mono text-xs uppercase tracking-widest text-muted">
            <Cpu size={12} /> Native Code Decompilation (Ghidra)
          </h3>
          <div className="mb-3 grid grid-cols-4 gap-3 font-mono text-xs">
            <Stat label=".so Files" value={ghidra.so_files_analyzed.length} />
            <Stat label="Hardcoded IPs" value={ghidra.hardcoded_ips.length} />
            <Stat label="Hardcoded URLs" value={ghidra.hardcoded_urls.length} />
            <Stat label="Secrets Found" value={ghidra.secrets_found.length} />
          </div>
          {ghidra.secrets_found.length > 0 && (
            <table className="data-table w-full">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>File</th>
                  <th>Preview</th>
                </tr>
              </thead>
              <tbody>
                {ghidra.secrets_found.map((s, i) => (
                  <tr key={i}>
                    <td>{s.type}</td>
                    <td className="break-all">{s.file}</td>
                    <td className="break-all">{s.match_preview}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {mobsf?.available && (
        <div>
          <h3 className="mb-3 flex items-center gap-2 font-mono text-xs uppercase tracking-widest text-muted">
            <ScanSearch size={12} /> MobSF Automated Scan
          </h3>
          <div className="mb-3 grid grid-cols-4 gap-3 font-mono text-xs">
            <Stat label="Security Score" value={mobsf.security_score ?? "n/a"} />
            <Stat label="Avg CVSS" value={mobsf.average_cvss ?? "n/a"} />
            <Stat label="Trackers" value={mobsf.trackers_detected.length} />
            <Stat label="Findings" value={mobsf.code_analysis_findings.length} />
          </div>
          {mobsf.code_analysis_findings.length > 0 && (
            <table className="data-table w-full">
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Severity</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
                {mobsf.code_analysis_findings.map((f, i) => (
                  <tr key={i}>
                    <td>{f.rule}</td>
                    <td>{f.severity}</td>
                    <td className="break-all">{f.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {!dex && !hasCodeReview && (
        <div className="font-mono text-xs text-muted">No code-review findings available.</div>
      )}
    </div>
  );
}

function BoolCard({ label, value }) {
  return (
    <div className="panel flex items-center justify-between p-3">
      <span className="font-mono text-xs text-ink">{label}</span>
      {value ? (
        <Check size={16} className="text-alarm" />
      ) : (
        <X size={16} className="text-muted" />
      )}
    </div>
  );
}

function Stat({ label, value }) {
  return (
    <div className="panel p-3 text-center">
      <div className="text-lg font-bold tabular-nums text-cyan">{value}</div>
      <div className="text-[10px] text-muted">{label}</div>
    </div>
  );
}
