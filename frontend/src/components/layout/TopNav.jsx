import { Link } from "react-router-dom";
import { ShieldCheck, WifiOff } from "lucide-react";
import { useEffect, useState } from "react";
import { useStore } from "../../lib/store";
import { getHealth } from "../../lib/api";

export default function TopNav() {
  const caseId = useStore((s) => s.caseId);
  const [ram, setRam] = useState(0);
  const [airGapped, setAirGapped] = useState(null); // null until /health responds

  useEffect(() => {
    // Best-effort client-side memory pressure proxy; the backend's own RAM
    // guardrails (utils/ram_monitor.py) are authoritative and surfaced via
    // per-stage artifacts during analysis. This bar is a lightweight ambient
    // indicator, not a duplicate of that check.
    if (performance?.memory) {
      const id = setInterval(() => {
        const { usedJSHeapSize, jsHeapSizeLimit } = performance.memory;
        setRam(Math.min(100, Math.round((usedJSHeapSize / jsHeapSizeLimit) * 100)));
      }, 3000);
      return () => clearInterval(id);
    }
  }, []);

  useEffect(() => {
    // GET /health reports the real AIR_GAP_MODE setting the backend booted with.
    let cancelled = false;
    const poll = () =>
      getHealth()
        .then((r) => !cancelled && setAirGapped(!!r.data.air_gap))
        .catch(() => !cancelled && setAirGapped(null));
    poll();
    const id = setInterval(poll, 15000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const ramColor = ram > 85 ? "bg-alarm" : ram > 60 ? "bg-amber" : "bg-neon";

  return (
    <header className="sticky top-0 z-40 border-b border-border bg-bg/95 backdrop-blur">
      <div className="flex items-center justify-between px-5 py-2.5">
        <Link to="/" className="flex items-center gap-2">
          <EagleMark />
          <span className="font-mono text-sm tracking-widest text-ink">GARUDATVA</span>
          <span className="rounded-none border border-crimson px-1.5 py-0.5 text-[10px] font-mono text-crimson">
            v3
          </span>
        </Link>

        <div className="font-mono text-xs text-muted">
          {caseId ? (
            <span>
              CASE <span className="text-cyan">{caseId.slice(0, 8)}</span>
            </span>
          ) : (
            <span className="opacity-50">NO ACTIVE CASE</span>
          )}
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] text-muted">RAM</span>
            <div className="h-1.5 w-24 overflow-hidden bg-border">
              <div
                className={`h-full transition-all duration-500 ${ramColor}`}
                style={{ width: `${ram}%` }}
              />
            </div>
          </div>
          <div
            className="flex items-center gap-1.5 font-mono text-[10px]"
            title="Reflects the backend's AIR_GAP_MODE setting from GET /health"
          >
            {airGapped === null ? (
              <span className="text-muted">BACKEND UNREACHABLE</span>
            ) : airGapped ? (
              <>
                <ShieldCheck size={13} className="text-neon" />
                <span className="text-neon">AIR-GAPPED</span>
              </>
            ) : (
              <>
                <WifiOff size={13} className="text-alarm" />
                <span className="text-alarm">NETWORK LIVE</span>
              </>
            )}
          </div>
        </div>
      </div>
    </header>
  );
}

function EagleMark() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
      <path
        d="M12 2 L3 9 L7 9 L4 20 L12 14 L20 20 L17 9 L21 9 Z"
        fill="#e94560"
        opacity="0.9"
      />
    </svg>
  );
}
