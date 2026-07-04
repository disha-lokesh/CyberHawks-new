import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Lock, Unlock, MessageSquare, Clipboard as ClipboardIcon } from "lucide-react";
import { useStore } from "../../lib/store.js";

// Real value spoofed by backend/core/dynamic/anti_evasion.py's DEVICE_PROFILE —
// not decorative, this is what the sandbox actually presents to the malware.
const SPOOFED_DEVICE = "HUAWEI Mate 40 Pro";

const HOOK_DOTS = [
  { key: "network", color: "#00d4ff" },
  { key: "crypto", color: "#f39c12" },
  { key: "sms", color: "#e94560" },
  { key: "clipboard", color: "#f39c12" },
  { key: "accessibility", color: "#ff2244" },
  { key: "permission", color: "#e94560" },
];

export default function SandboxVisualizer({ apkMeta, active }) {
  const lastEvent = useStore((s) => s.lastSandboxEvent);
  const hookCounts = useStore((s) => s.hookCounts);
  const forcedPermissions = useStore((s) => s.forcedPermissions);
  const monkeyTaps = useStore((s) => s.monkeyTaps);
  const resetSandbox = useStore((s) => s.resetSandbox);

  const [overlay, setOverlay] = useState(null); // transient event-driven overlay
  const [packetFlight, setPacketFlight] = useState(null);
  const [permDialog, setPermDialog] = useState(null);
  const [ripple, setRipple] = useState(null);
  const [dimmed, setDimmed] = useState(false);
  const [completeBadge, setCompleteBadge] = useState(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (active) {
      setVisible(true);
      setCompleteBadge(null);
    }
  }, [active]);

  useEffect(() => {
    if (!lastEvent) return;
    const { type, data } = lastEvent;

    if (type === "network_event") {
      setPacketFlight(data?.url || data?.host || "unknown");
      const t = setTimeout(() => setPacketFlight(null), 1800);
      return () => clearTimeout(t);
    }
    if (type === "sms_event") {
      setOverlay({ kind: "sms", label: "SMS INTERCEPT" });
      const t = setTimeout(() => setOverlay(null), 1500);
      return () => clearTimeout(t);
    }
    if (type === "clipboard_event") {
      setOverlay({ kind: "clipboard", label: "CLIPBOARD WRITE" });
      const t = setTimeout(() => setOverlay(null), 1500);
      return () => clearTimeout(t);
    }
    if (type === "crypto_event") {
      setOverlay({ kind: "crypto", label: "AES OPERATION" });
      const t = setTimeout(() => setOverlay(null), 1500);
      return () => clearTimeout(t);
    }
    if (type === "accessibility_event") {
      setDimmed(true);
      setOverlay({ kind: "accessibility", label: `ACCESSIBILITY EVENT — TYPE: ${data?.type || "UNKNOWN"}` });
      const t = setTimeout(() => {
        setDimmed(false);
        setOverlay(null);
      }, 1500);
      return () => clearTimeout(t);
    }
    if (type === "permission_request") {
      const perm = (data?.permissions || ["UNKNOWN"])[0];
      setPermDialog(perm);
      const t = setTimeout(() => setPermDialog(null), 1500);
      return () => clearTimeout(t);
    }
    if (type === "monkey_event" && (data?.action === "tap" || data?.action === "swipe")) {
      setRipple({ x: data.x ?? 50, y: data.y ?? 50, id: Date.now() });
      const t = setTimeout(() => setRipple(null), 800);
      return () => clearTimeout(t);
    }
    if (type === "sandbox_complete") {
      setCompleteBadge(data?.artifact_count ?? 0);
      const t = setTimeout(() => setVisible(false), 2000);
      return () => clearTimeout(t);
    }
  }, [lastEvent]);

  if (!visible) {
    return (
      <div className="panel flex h-full min-h-[220px] items-center justify-center p-4 font-mono text-[11px] text-muted">
        Sandbox visualizer activates during DYNAMIC ANALYSIS
      </div>
    );
  }

  return (
    <div className="panel flex h-full flex-col items-center gap-3 p-4">
      <div className="flex items-center gap-2">
        <span className="font-mono text-[10px] text-amber">SANDBOX — {SPOOFED_DEVICE}</span>
        <span className="relative flex h-2 w-2">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-neon opacity-75" />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-neon" />
        </span>
        <span className="font-mono text-[9px] text-neon">LIVE</span>
      </div>

      {/* Phone shell */}
      <div
        className={`relative h-[300px] w-[150px] rounded-[20px] border-[3px] border-[#1a1a2e] bg-[#0a0a0f] transition-shadow ${
          dimmed ? "" : "shadow-[inset_0_0_18px_rgba(233,69,96,0.35)]"
        }`}
      >
        {/* punch-hole camera */}
        <div className="absolute left-1/2 top-1.5 h-1.5 w-1.5 -translate-x-1/2 rounded-full bg-black ring-1 ring-white/10" />
        {/* status bar */}
        <div className="absolute left-0 right-0 top-0 flex h-4 items-center justify-between px-2 pt-1 text-[7px] text-white/90">
          <span>12:00</span>
          <span>▮▮▮ ᖴ 100%</span>
        </div>

        {/* screen */}
        <div className={`absolute inset-x-1.5 bottom-1.5 top-5 overflow-hidden rounded-b-[14px] rounded-t-sm bg-[#12121c] transition-opacity ${dimmed ? "opacity-30" : "opacity-100"}`}>
          {/* toolbar */}
          <div className="flex h-5 items-center border-b border-white/5 bg-[#1a1a2e] px-1.5 text-[7px] text-white/70">
            {apkMeta?.filename?.replace(/\.apk$/i, "") || "target.app"}
          </div>

          {/* wireframe content */}
          <div className="flex flex-col gap-1.5 p-2">
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                className={`h-4 rounded-sm border transition-colors ${
                  lastEvent?.type === "accessibility_event" && i === 0
                    ? "border-cyan"
                    : "border-white/15"
                }`}
              >
                {i === 0 && (
                  <span className="ml-1 inline-block h-2 w-px animate-blinkCursor bg-cyan align-middle" />
                )}
              </div>
            ))}
          </div>

          {/* touch ripple */}
          <AnimatePresence>
            {ripple && (
              <motion.span
                key={ripple.id}
                className="absolute h-6 w-6 rounded-full border border-cyan"
                style={{
                  left: `${(ripple.x / 1080) * 100}%`,
                  top: `${(ripple.y / 2220) * 100}%`,
                }}
                initial={{ scale: 0, opacity: 0.7 }}
                animate={{ scale: 3, opacity: 0 }}
                transition={{ duration: 0.7 }}
              />
            )}
          </AnimatePresence>

          {/* accessibility overlay */}
          <AnimatePresence>
            {dimmed && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="absolute inset-0 flex items-center justify-center bg-alarm/20 p-2 text-center font-mono text-[7px] text-alarm"
              >
                {overlay?.label}
              </motion.div>
            )}
          </AnimatePresence>

          {/* permission dialog */}
          <AnimatePresence>
            {permDialog && (
              <motion.div
                initial={{ y: 60, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                exit={{ y: 60, opacity: 0, backgroundColor: "#ff2244" }}
                className="absolute inset-x-1 bottom-1 rounded-t-md bg-[#1e1e2e] p-2 text-[7px] text-white"
              >
                <div className="mb-1 h-3 w-3 rounded-full bg-white/20" />
                <div className="mb-1 font-semibold">Allow access?</div>
                <div className="mb-1.5 text-white/70">{permDialog}</div>
                <div className="flex justify-end gap-1">
                  <span className="border border-white/30 px-1.5 py-0.5">DENY</span>
                  <span className="bg-crimson px-1.5 py-0.5">ALLOW</span>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* completion badge */}
        <AnimatePresence>
          {completeBadge !== null && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 flex items-center justify-center bg-black/85 p-3 text-center font-mono text-[8px] text-neon"
            >
              DYNAMIC ANALYSIS COMPLETE
              <br />
              {completeBadge} ARTIFACTS CAPTURED
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Floating badges outside phone */}
      <div className="flex h-4 items-center">
        <AnimatePresence>
          {packetFlight && (
            <motion.div
              initial={{ y: 10, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              exit={{ opacity: 0 }}
              className="max-w-[180px] truncate border border-crimson bg-black/60 px-2 py-0.5 font-mono text-[9px] text-crimson"
            >
              {packetFlight}
            </motion.div>
          )}
          {overlay?.kind === "crypto" && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="flex items-center gap-1 font-mono text-[9px] text-amber">
              <Unlock size={11} /> {overlay.label}
            </motion.div>
          )}
          {overlay?.kind === "sms" && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="flex items-center gap-1 font-mono text-[9px] text-crimson">
              <MessageSquare size={11} /> {overlay.label}
            </motion.div>
          )}
          {overlay?.kind === "clipboard" && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="flex items-center gap-1 font-mono text-[9px] text-amber">
              <ClipboardIcon size={11} /> {overlay.label}
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Hook status dots */}
      <div className="flex items-center gap-1.5 font-mono text-[9px] text-muted">
        FRIDA HOOKS ACTIVE
        {HOOK_DOTS.map((h) => (
          <span
            key={h.key}
            title={h.key}
            className="h-2 w-2 rounded-full transition-colors"
            style={{
              backgroundColor: hookCounts[h.key] > 0 ? h.color : "#2a2a3a",
              boxShadow: hookCounts[h.key] > 0 ? `0 0 6px ${h.color}` : "none",
            }}
          />
        ))}
      </div>
      <div className="flex flex-wrap justify-center gap-x-2 gap-y-0.5 font-mono text-[8px] text-muted">
        {HOOK_DOTS.map((h) => (
          <span key={h.key}>
            {h.key.toUpperCase()}: {hookCounts[h.key]}
          </span>
        ))}
      </div>

      {forcedPermissions.length > 0 && (
        <div className="flex flex-wrap justify-center gap-1">
          {forcedPermissions.slice(-6).map((p, i) => (
            <motion.span
              key={`${p}-${i}`}
              initial={{ scale: 0.5, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              className="border border-alarm px-1.5 py-0.5 font-mono text-[8px] text-alarm"
            >
              FORCED: {p.replace("android.permission.", "")}
            </motion.span>
          ))}
        </div>
      )}
    </div>
  );
}
