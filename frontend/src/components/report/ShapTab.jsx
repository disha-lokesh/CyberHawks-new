import { useState } from "react";
import { motion } from "framer-motion";

const EXPLAIN = {
  perm_BIND_ACCESSIBILITY_SERVICE: "The app declares an Accessibility Service, the #1 technique in Indian banking trojans for keylogging and screen scraping.",
  perm_READ_SMS: "The app can read incoming SMS — the standard mechanism for stealing OTPs.",
  dex_dynamic_loading: "The app loads additional code at runtime (DexClassLoader), often used to hide payloads from static scanners.",
  dex_reflection_used: "The app uses Java reflection to call methods indirectly, a common obfuscation technique.",
  yara_banking_trojan_hit: "A YARA rule targeting known banking-trojan string patterns matched.",
  native_frida_detection: "The app's native code checks for Frida — a sign it expects to be dynamically analyzed and tries to evade it.",
  cert_is_self_signed: "The signing certificate is self-signed rather than issued by a recognised authority.",
  net_domain_fronting_detected: "Network traffic showed a mismatch between the TLS SNI and the HTTP Host header — a technique for hiding the true destination.",
};

export default function ShapTab({ riskScore }) {
  const features = (riskScore?.shap_features || []).slice(0, 20);
  const [selected, setSelected] = useState(null);
  const maxAbs = Math.max(0.001, ...features.map((f) => Math.abs(f.shap_value)));

  if (features.length === 0) {
    return (
      <div className="font-mono text-xs text-muted">
        No SHAP features available — the ML classifier is running on the heuristic fallback
        (no trained model deployed), which doesn't produce SHAP explanations.
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {features.map((f, i) => {
        const pct = (Math.abs(f.shap_value) / maxAbs) * 100;
        const positive = f.shap_value >= 0;
        return (
          <div key={f.feature_name} className="relative">
            <button
              onClick={() => setSelected(f)}
              className="flex w-full items-center gap-3 py-1 text-left"
            >
              <span className="w-56 shrink-0 truncate font-mono text-[11px] text-muted">
                {f.feature_name}
              </span>
              <div className="relative h-4 flex-1 bg-border">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${pct}%` }}
                  transition={{ duration: 0.8, delay: i * 0.02, ease: "easeOut" }}
                  className={`h-full ${positive ? "bg-crimson" : "bg-cyan"}`}
                />
              </div>
              <span className="w-16 shrink-0 text-right font-mono text-[11px] tabular-nums text-ink">
                {f.shap_value.toFixed(3)}
              </span>
            </button>
          </div>
        );
      })}

      {selected && (
        <div className="panel mt-4 p-4">
          <div className="font-mono text-xs text-ink">{selected.feature_name}</div>
          <div className="mt-1 font-mono text-[10px] text-muted">
            value = {selected.feature_value} · SHAP = {selected.shap_value.toFixed(4)} · rank #{selected.rank}
          </div>
          <div className="mt-2 text-xs text-ink/80">
            {EXPLAIN[selected.feature_name] || "Contributed to the model's malware-probability estimate — see the feature name for its raw meaning."}
          </div>
        </div>
      )}
    </div>
  );
}
