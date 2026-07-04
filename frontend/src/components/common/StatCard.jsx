import AnimatedNumber from "./AnimatedNumber";

export default function StatCard({ label, value, accent = "cyan", icon: Icon }) {
  const accentClass = { cyan: "text-cyan", crimson: "text-crimson", neon: "text-neon", amber: "text-amber" }[accent];
  return (
    <div className="panel flex items-center justify-between p-3">
      <div>
        <div className="font-mono text-[10px] uppercase tracking-wider text-muted">{label}</div>
        <div className={`font-mono text-2xl font-bold tabular-nums ${accentClass}`}>
          <AnimatedNumber value={value} />
        </div>
      </div>
      {Icon && <Icon size={20} className={accentClass} />}
    </div>
  );
}
