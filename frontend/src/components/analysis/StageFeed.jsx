import { useEffect, useRef } from "react";

export default function StageFeed({ lines }) {
  const endRef = useRef(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [lines.length]);

  return (
    <div className="scanline-container panel h-full overflow-y-auto p-4 font-mono text-xs">
      {lines.length === 0 && <div className="text-muted">awaiting pipeline output…</div>}
      {lines.map((l, i) => (
        <div key={i} className="mb-1 leading-relaxed">
          <span className="text-cyan">{new Date(l.ts).toLocaleTimeString()}</span>{" "}
          <span className="text-crimson">[{l.stage}]</span>{" "}
          <span className="text-ink">{l.text}</span>
        </div>
      ))}
      <div ref={endRef} />
    </div>
  );
}
