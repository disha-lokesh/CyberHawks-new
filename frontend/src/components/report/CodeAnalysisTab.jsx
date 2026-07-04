import { useState } from "react";
import { Check, X, Search } from "lucide-react";

export default function CodeAnalysisTab({ staticResult }) {
  const dex = staticResult?.dex;
  const [query, setQuery] = useState("");
  const [sortDesc, setSortDesc] = useState(true);

  if (!dex) return <div className="font-mono text-xs text-muted">DEX analysis unavailable.</div>;

  const rows = [
    ...dex.urls.map((v) => ({ type: "URL", value: v })),
    ...dex.ips.map((v) => ({ type: "IP", value: v })),
  ].filter((r) => r.value.toLowerCase().includes(query.toLowerCase()));

  if (!sortDesc) rows.reverse();

  return (
    <div className="space-y-8">
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
