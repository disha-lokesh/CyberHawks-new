import { motion } from "framer-motion";
import AnimatedNumber from "./AnimatedNumber";

const TIER_COLOR = {
  BENIGN: "#00ff88",
  SUSPICIOUS: "#f39c12",
  HIGH_RISK: "#e67e22",
  CRITICAL: "#ff2244",
};

function tierOf(score) {
  if (score >= 85) return "CRITICAL";
  if (score >= 65) return "HIGH_RISK";
  if (score >= 30) return "SUSPICIOUS";
  return "BENIGN";
}

export default function RadialGauge({ score = 0, tier, size = 260 }) {
  const resolvedTier = tier || tierOf(score);
  const color = TIER_COLOR[resolvedTier] || "#6b6b8a";
  const r = size / 2 - 14;
  const circumference = 2 * Math.PI * r;
  const sweep = Math.max(0, Math.min(100, score)) / 100;
  const isCritical = resolvedTier === "CRITICAL";

  return (
    <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke="#1a1a2e"
          strokeWidth={14}
        />
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={14}
          strokeLinecap="butt"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: circumference * (1 - sweep) }}
          transition={{ duration: 1, ease: "easeOut" }}
          style={{ filter: `drop-shadow(0 0 8px ${color}aa)` }}
          className={isCritical ? "animate-pulseBorder" : ""}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <div className="font-mono text-4xl font-bold tabular-nums" style={{ color }}>
          <AnimatedNumber value={score || 0} decimals={1} />
        </div>
        <div
          className="mt-2 rounded-none border px-3 py-1 font-mono text-xs tracking-widest"
          style={{ color, borderColor: color, backgroundColor: `${color}14` }}
        >
          {resolvedTier}
        </div>
      </div>
    </div>
  );
}
