import { useState } from "react";
import { ChevronDown } from "lucide-react";

const COMPONENTS = [
  { key: "ml_score", label: "ML Classifier", max: 35 },
  { key: "syscall_score", label: "Syscall Profile", max: 15 },
  { key: "yara_score", label: "YARA Matches", max: 20 },
  { key: "permission_score", label: "Toxic Permissions", max: 10 },
  { key: "india_pattern_score", label: "India Patterns", max: 10 },
  { key: "cert_score", label: "Certificate Anomalies", max: 5 },
  { key: "manifest_score", label: "Manifest Obfuscation", max: 5 },
];

export default function OverviewTab({ staticResult }) {
  const rs = staticResult?.risk_score;
  const indiaMatches = staticResult?.india_matches || [];
  const yaraMatches = staticResult?.yara?.matches || [];

  const byCategory = groupBy(indiaMatches, "category");
  const yaraByCategory = groupBy(yaraMatches, "category");

  return (
    <div className="space-y-8">
      <div className="grid grid-cols-4 gap-3">
        {COMPONENTS.map((c) => (
          <ScoreCard key={c.key} label={c.label} value={rs?.[c.key] ?? 0} max={c.max} />
        ))}
      </div>

      <div>
        <h3 className="mb-3 font-mono text-xs uppercase tracking-widest text-muted">
          India Fraud Pattern Matches
        </h3>
        <div className="space-y-1">
          {Object.entries(byCategory).length === 0 && (
            <div className="font-mono text-xs text-muted">No India-specific patterns matched.</div>
          )}
          {Object.entries(byCategory).map(([cat, matches]) => (
            <Accordion key={cat} title={`${cat} (${matches.length})`}>
              {matches.map((m, i) => (
                <div key={i} className="border-b border-border/40 py-2">
                  <div className="font-mono text-xs text-ink">{m.pattern_name}</div>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {m.matched_strings.slice(0, 5).map((s, j) => (
                      <span key={j} className="border border-crimson/50 px-1.5 py-0.5 font-mono text-[10px] text-crimson">
                        {s}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </Accordion>
          ))}
        </div>
      </div>

      <div>
        <h3 className="mb-3 font-mono text-xs uppercase tracking-widest text-muted">YARA Matches</h3>
        <div className="flex flex-wrap gap-2">
          {Object.entries(yaraByCategory).length === 0 && (
            <div className="font-mono text-xs text-muted">No YARA rules matched.</div>
          )}
          {Object.entries(yaraByCategory).map(([cat, matches]) => (
            <span key={cat} className="border border-amber/60 bg-amber/5 px-3 py-1 font-mono text-xs text-amber">
              {cat} × {matches.length}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

function ScoreCard({ label, value, max }) {
  const pct = Math.min(100, (value / max) * 100);
  return (
    <div className="panel group relative p-3" title={`${value.toFixed(1)} / ${max} contribution`}>
      <div className="mb-2 flex items-center justify-center">
        <svg width="48" height="48" className="-rotate-90">
          <circle cx="24" cy="24" r="20" fill="none" stroke="#1a1a2e" strokeWidth="5" />
          <circle
            cx="24" cy="24" r="20" fill="none" stroke="#00d4ff" strokeWidth="5"
            strokeDasharray={2 * Math.PI * 20}
            strokeDashoffset={2 * Math.PI * 20 * (1 - pct / 100)}
          />
        </svg>
      </div>
      <div className="text-center font-mono text-xs text-ink">
        {value.toFixed(1)}/{max}
      </div>
      <div className="text-center font-mono text-[10px] text-muted">{label}</div>
    </div>
  );
}

function Accordion({ title, children }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="panel">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between p-3 font-mono text-xs text-ink"
      >
        {title}
        <ChevronDown size={14} className={`transition-transform ${open ? "rotate-180" : ""}`} />
      </button>
      {open && <div className="border-t border-border px-3 pb-2">{children}</div>}
    </div>
  );
}

function groupBy(arr, key) {
  return arr.reduce((acc, item) => {
    (acc[item[key]] ||= []).push(item);
    return acc;
  }, {});
}
