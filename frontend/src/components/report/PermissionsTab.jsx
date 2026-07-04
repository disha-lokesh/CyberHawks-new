import { AlertTriangle } from "lucide-react";

// Category labels for the real toxic-permission set defined in
// backend/core/static/manifest_parser.py's TOXIC_PERMISSIONS.
const CATEGORY = {
  READ_SMS: ["SMS Theft", 9], RECEIVE_SMS: ["SMS Theft", 9], SEND_SMS: ["SMS Theft", 8],
  READ_CONTACTS: ["Data Harvest", 5], READ_CALL_LOG: ["Data Harvest", 5],
  PROCESS_OUTGOING_CALLS: ["Call Interception", 7], RECORD_AUDIO: ["Surveillance", 8],
  CAMERA: ["Surveillance", 6], READ_EXTERNAL_STORAGE: ["Data Harvest", 4],
  WRITE_EXTERNAL_STORAGE: ["Data Harvest", 4], ACCESS_FINE_LOCATION: ["Location Tracking", 6],
  ACCESS_BACKGROUND_LOCATION: ["Location Tracking", 8], SYSTEM_ALERT_WINDOW: ["Overlay", 9],
  BIND_ACCESSIBILITY_SERVICE: ["Keylogging", 10], BIND_DEVICE_ADMIN: ["Device Admin Abuse", 9],
  REQUEST_INSTALL_PACKAGES: ["Dropper", 8], READ_PHONE_STATE: ["Device Fingerprint", 3],
  USE_BIOMETRIC: ["Auth Bypass", 5], USE_FINGERPRINT: ["Auth Bypass", 5],
  CHANGE_NETWORK_STATE: ["Network Manipulation", 4], FOREGROUND_SERVICE: ["Persistence", 3],
  RECEIVE_BOOT_COMPLETED: ["Persistence", 6], DISABLE_KEYGUARD: ["Lockscreen Bypass", 7],
};

const TOXIC_COMBOS = [
  { combo: ["READ_SMS", "INTERNET", "RECEIVE_BOOT_COMPLETED"], label: "Banking Trojan Pattern" },
  { combo: ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"], label: "Overlay + Keylogger Pattern" },
  { combo: ["BIND_DEVICE_ADMIN", "REQUEST_INSTALL_PACKAGES"], label: "Ransomware/Dropper Pattern" },
];

export default function PermissionsTab({ staticResult }) {
  const perms = staticResult?.manifest?.permissions || [];
  const toxic = staticResult?.manifest?.toxic_permissions || [];
  const short = (p) => p.replace("android.permission.", "");
  const toxicShort = new Set(toxic.map(short));

  const combosPresent = TOXIC_COMBOS.filter((c) => c.combo.every((p) => toxicShort.has(p)));

  return (
    <div className="space-y-8">
      <div>
        <h3 className="mb-3 font-mono text-xs uppercase tracking-widest text-muted">
          Toxic Permission Matrix ({toxic.length} of {perms.length} declared)
        </h3>
        <div className="grid grid-cols-3 gap-3">
          {toxic.map((p) => {
            const s = short(p);
            const [cat, weight] = CATEGORY[s] || ["Uncategorized", 3];
            return (
              <div key={p} className="panel p-3">
                <div className="font-mono text-xs text-ink">{s}</div>
                <div className="mt-1 font-mono text-[10px] text-muted">{cat}</div>
                <div className="mt-2 h-1.5 w-full bg-border">
                  <div className="h-full bg-crimson" style={{ width: `${weight * 10}%` }} />
                </div>
              </div>
            );
          })}
          {toxic.length === 0 && <div className="font-mono text-xs text-muted">No toxic permissions declared.</div>}
        </div>
      </div>

      {combosPresent.length > 0 && (
        <div>
          <h3 className="mb-3 flex items-center gap-2 font-mono text-xs uppercase tracking-widest text-alarm">
            <AlertTriangle size={14} /> Toxic Combinations Detected
          </h3>
          <div className="space-y-2">
            {combosPresent.map((c) => (
              <div key={c.label} className="border border-alarm/50 bg-alarm/5 p-3">
                <div className="font-mono text-xs text-alarm">{c.label}</div>
                <div className="mt-1 font-mono text-[10px] text-muted">{c.combo.join(" + ")}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
