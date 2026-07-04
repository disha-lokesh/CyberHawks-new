import { AnimatePresence, motion } from "framer-motion";
import { AlertTriangle, CheckCircle2, Info, X } from "lucide-react";
import { useStore } from "../../lib/store";
import { useEffect } from "react";

const ICONS = { success: CheckCircle2, warning: AlertTriangle, info: Info };
const COLORS = { success: "text-neon border-neon", warning: "text-amber border-amber", info: "text-cyan border-cyan" };

export default function ToastStack() {
  const toasts = useStore((s) => s.toasts);
  const dismissToast = useStore((s) => s.dismissToast);

  return (
    <div className="pointer-events-none fixed right-4 top-16 z-50 flex flex-col gap-2">
      <AnimatePresence>
        {toasts.map((t) => (
          <ToastItem key={t.id} toast={t} onDismiss={() => dismissToast(t.id)} />
        ))}
      </AnimatePresence>
    </div>
  );
}

function ToastItem({ toast, onDismiss }) {
  const Icon = ICONS[toast.variant] || Info;
  useEffect(() => {
    const id = setTimeout(onDismiss, toast.duration || 5000);
    return () => clearTimeout(id);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <motion.div
      initial={{ x: 60, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: 60, opacity: 0 }}
      transition={{ duration: 0.2, ease: "easeOut" }}
      className={`panel pointer-events-auto flex w-80 items-start gap-2 border-l-2 p-3 ${COLORS[toast.variant] || COLORS.info}`}
    >
      <Icon size={16} className="mt-0.5 shrink-0" />
      <div className="flex-1 text-xs text-ink">
        {toast.title && <div className="font-semibold">{toast.title}</div>}
        <div className="text-muted">{toast.message}</div>
      </div>
      <button onClick={onDismiss} className="text-muted hover:text-ink">
        <X size={14} />
      </button>
    </motion.div>
  );
}
