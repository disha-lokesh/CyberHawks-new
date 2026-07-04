import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import ForceGraph, { NODE_STYLE } from "../components/syndicate/ForceGraph.jsx";
import { getIocGraph, searchSyndicates } from "../lib/api.js";
import { useStore } from "../lib/store.js";
import { RefreshCcw } from "lucide-react";

export default function Syndicate() {
  const [params] = useSearchParams();
  const analysisId = useStore((s) => s.analysisId);
  const [graph, setGraph] = useState({ nodes: [], edges: [] });
  const [selected, setSelected] = useState(null);
  const [district, setDistrict] = useState("");
  const [searchResults, setSearchResults] = useState([]);
  const [error, setError] = useState(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    if (!analysisId) return;
    getIocGraph(analysisId)
      .then((r) => setGraph(r.data))
      .catch((e) => setError(e?.response?.data?.detail || "Graph unavailable — is Neo4j running?"));
  }, [analysisId, reloadKey]);

  useEffect(() => {
    const value = params.get("value");
    if (value) {
      searchSyndicates({ ip: value }).then((r) => setSearchResults(r.data.syndicates || []));
    }
  }, [params]);

  return (
    <div className="relative h-[calc(100vh-52px)]">
      {/* Controls */}
      <div className="panel absolute left-4 top-4 z-10 w-72 space-y-3 p-4">
        <h3 className="font-mono text-xs uppercase tracking-widest text-muted">Cross-District Search</h3>
        <input
          value={district}
          onChange={(e) => setDistrict(e.target.value)}
          placeholder="District…"
          className="w-full border-b border-border bg-transparent px-1 py-1.5 font-mono text-xs outline-none focus:border-cyan"
        />
        <button
          onClick={() => searchSyndicates({ district }).then((r) => setSearchResults(r.data.syndicates || []))}
          className="w-full border border-cyan py-1.5 font-mono text-[10px] tracking-widest text-cyan hover:bg-cyan hover:text-black"
        >
          SEARCH SYNDICATES
        </button>
        <button
          onClick={() => setReloadKey((k) => k + 1)}
          className="flex w-full items-center justify-center gap-1.5 border border-border py-1.5 font-mono text-[10px] tracking-widest text-muted hover:text-ink"
        >
          <RefreshCcw size={11} /> RESET LAYOUT
        </button>

        {searchResults.length > 0 && (
          <div className="space-y-1 border-t border-border pt-2">
            {searchResults.map((r, i) => (
              <div key={i} className="font-mono text-[10px] text-ink">
                <span className="text-crimson">{r.link_type}</span> — {r.package_name || r.matching_ips?.join(", ")}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="panel absolute bottom-4 right-4 z-10 space-y-1 p-3">
        {Object.entries(NODE_STYLE).map(([label, style]) => (
          <div key={label} className="flex items-center gap-2 font-mono text-[10px] text-muted">
            <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ backgroundColor: style.color }} />
            {label}
          </div>
        ))}
      </div>

      {/* Node detail panel */}
      {selected && (
        <div className="panel absolute right-4 top-4 z-10 w-72 p-4">
          <h3 className="font-mono text-xs uppercase tracking-widest text-crimson">
            {selected.labels?.[0]}
          </h3>
          <div className="mt-2 space-y-1 font-mono text-[10px] text-ink">
            {Object.entries(selected.properties || {}).map(([k, v]) => (
              <div key={k} className="flex justify-between gap-2">
                <span className="text-muted">{k}</span>
                <span className="break-all text-right">{String(v)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {!analysisId && (
        <div className="flex h-full items-center justify-center font-mono text-xs text-muted">
          No active analysis — upload an APK to populate the graph, or use cross-district search.
        </div>
      )}
      {analysisId && error && (
        <div className="flex h-full items-center justify-center font-mono text-xs text-alarm">{error}</div>
      )}
      {analysisId && !error && (
        <ForceGraph nodes={graph.nodes} edges={graph.edges} onNodeClick={setSelected} />
      )}
    </div>
  );
}
