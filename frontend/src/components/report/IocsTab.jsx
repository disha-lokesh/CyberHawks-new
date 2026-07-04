import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Copy, Search, Cloud } from "lucide-react";

export default function IocsTab({ staticResult, dynamicResult }) {
  const navigate = useNavigate();
  const [filter, setFilter] = useState("ALL");

  const iocs = useMemo(() => {
    const s = staticResult?.iocs || [];
    const d = dynamicResult?.iocs || [];
    return [...s, ...d];
  }, [staticResult, dynamicResult]);

  const types = ["ALL", ...new Set(iocs.map((i) => i.ioc_type))];
  const filtered = filter === "ALL" ? iocs : iocs.filter((i) => i.ioc_type === filter);

  return (
    <div>
      <div className="mb-4 flex gap-2">
        {types.map((t) => (
          <button
            key={t}
            onClick={() => setFilter(t)}
            className={`border px-3 py-1 font-mono text-[10px] uppercase tracking-wider transition ${
              filter === t ? "border-crimson text-crimson" : "border-border text-muted"
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      <table className="data-table w-full">
        <thead>
          <tr>
            <th>Type</th>
            <th>Value</th>
            <th>Source</th>
            <th>Cloud</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((ioc, i) => (
            <tr key={i}>
              <td>{ioc.ioc_type}</td>
              <td className="break-all">{ioc.value}</td>
              <td className="text-muted">{ioc.source}</td>
              <td>
                {ioc.cloud_provider && ioc.cloud_provider !== "NOT_CLOUD" && (
                  <span className="flex items-center gap-1 text-cyan">
                    <Cloud size={11} /> {ioc.cloud_provider}
                  </span>
                )}
              </td>
              <td>
                <div className="flex gap-2">
                  <button onClick={() => navigator.clipboard.writeText(ioc.value)} className="text-muted hover:text-ink">
                    <Copy size={13} />
                  </button>
                  <button
                    onClick={() => navigate(`/syndicate?value=${encodeURIComponent(ioc.value)}`)}
                    className="text-muted hover:text-cyan"
                    title="Search in Graph"
                  >
                    <Search size={13} />
                  </button>
                </div>
              </td>
            </tr>
          ))}
          {filtered.length === 0 && (
            <tr>
              <td colSpan={5} className="text-muted">No IOCs of this type.</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
