import { motion } from "framer-motion";

export function WizardShell({ step, totalSteps, labels, children }) {
  return (
    <div className="mx-auto max-w-3xl px-6 py-10">
      <Stepper step={step} totalSteps={totalSteps} labels={labels} />
      <motion.div
        key={step}
        initial={{ x: 40, opacity: 0 }}
        animate={{ x: 0, opacity: 1 }}
        exit={{ x: -40, opacity: 0 }}
        transition={{ duration: 0.25, ease: "easeOut" }}
        className="panel mt-8 p-8"
      >
        {children}
      </motion.div>
    </div>
  );
}

function Stepper({ step, totalSteps, labels }) {
  return (
    <div className="flex items-center">
      {Array.from({ length: totalSteps }).map((_, i) => {
        const n = i + 1;
        const done = n < step;
        const active = n === step;
        return (
          <div key={n} className="flex flex-1 items-center last:flex-none">
            <div className="flex flex-col items-center gap-1.5">
              <div
                className={`flex h-8 w-8 items-center justify-center rounded-full border font-mono text-xs transition-all ${
                  active
                    ? "border-crimson bg-crimson/15 text-crimson shadow-glowCrimson"
                    : done
                    ? "border-neon bg-neon/10 text-neon"
                    : "border-border text-muted"
                }`}
              >
                {done ? (
                  <motion.span initial={{ scale: 0 }} animate={{ scale: 1 }}>
                    ✓
                  </motion.span>
                ) : (
                  n
                )}
              </div>
              <span className={`font-mono text-[10px] ${active ? "text-crimson" : "text-muted"}`}>
                {labels[i]}
              </span>
            </div>
            {n < totalSteps && (
              <div className={`mx-2 h-px flex-1 ${done ? "bg-neon" : "bg-border"}`} />
            )}
          </div>
        );
      })}
    </div>
  );
}

export function Field({ label, ...props }) {
  return (
    <label className="block">
      <span className="mb-1 block font-mono text-[10px] uppercase tracking-wider text-muted">
        {label}
      </span>
      <input
        {...props}
        className="w-full border-b border-border bg-transparent px-1 py-2 font-mono text-sm text-ink outline-none transition-colors focus:border-cyan focus:shadow-[0_1px_0_0_#00d4ff]"
      />
    </label>
  );
}
