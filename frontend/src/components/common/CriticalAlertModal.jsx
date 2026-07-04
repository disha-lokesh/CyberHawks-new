import { AnimatePresence, motion } from "framer-motion";
import { AlertOctagon } from "lucide-react";
import { useStore } from "../../lib/store";

export default function CriticalAlertModal() {
  const open = useStore((s) => s.criticalAlertOpen);
  const dismiss = useStore((s) => s.dismissCriticalAlert);
  const riskScore = useStore((s) => s.riskScore);

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-sm"
        >
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.9, opacity: 0 }}
            className="panel w-[420px] animate-pulseBorder border-2 border-alarm p-8 text-center"
          >
            <AlertOctagon size={48} className="mx-auto mb-4 text-alarm" />
            <div className="font-mono text-2xl font-bold tracking-wide text-alarm">
              CRITICAL RISK TIER
            </div>
            <div className="mt-2 font-mono text-sm text-muted">
              Risk score {riskScore?.toFixed?.(1) ?? "--"} / 100 — immediate enforcement
              action recommended. Preserve seized device. Do not power off.
            </div>
            <button
              onClick={dismiss}
              className="mt-6 border border-alarm px-6 py-2 font-mono text-xs tracking-widest text-alarm transition hover:bg-alarm hover:text-black"
            >
              ACKNOWLEDGE
            </button>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
