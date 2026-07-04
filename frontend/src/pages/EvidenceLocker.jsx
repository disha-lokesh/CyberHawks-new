import { useEffect, useState } from "react";
import { CheckCircle2, XCircle, MapPin } from "lucide-react";
import { uploadEvidenceVideo, getEvidenceManifest } from "../lib/api.js";
import { sha256File } from "../lib/hash.js";
import { useStore } from "../lib/store.js";

export default function EvidenceLocker() {
  const caseId = useStore((s) => s.caseId);
  const caseMetadata = useStore((s) => s.caseMetadata);
  const pushToast = useStore((s) => s.pushToast);

  const [file, setFile] = useState(null);
  const [preview, setPreview] = useState(null);
  const [witnesses, setWitnesses] = useState([]);
  const [witnessInput, setWitnessInput] = useState("");
  const [manifest, setManifest] = useState({ items: [] });
  const [uploading, setUploading] = useState(false);
  const [verifyState, setVerifyState] = useState({}); // itemId -> "ok" | "mismatch" | "checking"

  useEffect(() => {
    if (!caseId) return;
    refreshManifest();
  }, [caseId]);

  function refreshManifest() {
    getEvidenceManifest(caseId).then((r) => setManifest(r.data));
  }

  function handleDrop(f) {
    setFile(f);
    setPreview(URL.createObjectURL(f));
  }

  async function submit() {
    if (!caseId || !file) return;
    setUploading(true);
    try {
      await uploadEvidenceVideo({
        case_id: caseId,
        officer_badge: caseMetadata?.reporting_officer?.badge_id || "",
        gps_lat: caseMetadata?.seizure_gps_lat || 0,
        gps_lon: caseMetadata?.seizure_gps_lon || 0,
        witnesses: witnesses.join(","),
        file,
      });
      pushToast({ variant: "success", message: "Evidence ingested" });
      setFile(null);
      setPreview(null);
      refreshManifest();
    } catch (e) {
      pushToast({ variant: "warning", message: e?.response?.data?.detail || e.message });
    } finally {
      setUploading(false);
    }
  }

  // Verification re-hashes a file the officer picks from disk (the original
  // source, or a copy of the stored evidence) and compares it against the
  // manifest's recorded SHA256 — a real integrity check, not a fixed "ok".
  async function verify(item, file) {
    setVerifyState((s) => ({ ...s, [item.item_id]: "checking" }));
    const hash = await sha256File(file);
    setVerifyState((s) => ({ ...s, [item.item_id]: hash === item.sha256 ? "ok" : "mismatch" }));
  }

  return (
    <div className="mx-auto max-w-4xl space-y-8 p-8">
      <h2 className="font-mono text-lg text-ink">BNSS SECTION 176(3) — EVIDENCE LOCKER</h2>

      <div
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          e.preventDefault();
          const f = e.dataTransfer.files?.[0];
          if (f) handleDrop(f);
        }}
        className="border-2 border-dashed border-border p-8 text-center"
      >
        <input
          type="file"
          accept="video/*"
          id="evidence-video"
          className="hidden"
          onChange={(e) => e.target.files?.[0] && handleDrop(e.target.files[0])}
        />
        <label htmlFor="evidence-video" className="cursor-pointer font-mono text-xs text-muted">
          Drag seizure video, or click to browse
        </label>
        {preview && <video src={preview} controls className="mx-auto mt-4 max-h-48" />}
      </div>

      <div className="flex items-center gap-2 font-mono text-xs text-muted">
        <MapPin size={14} />
        {caseMetadata?.seizure_gps_lat
          ? `${caseMetadata.seizure_gps_lat.toFixed(5)}, ${caseMetadata.seizure_gps_lon.toFixed(5)}`
          : "no GPS on file for this case"}
        <span className="text-[10px] italic">
          (numeric only — no live map tiles on an air-gapped workstation)
        </span>
      </div>

      <div>
        <div className="mb-2 flex flex-wrap gap-2">
          {witnesses.map((w, i) => (
            <span key={i} className="border border-cyan px-2 py-0.5 font-mono text-xs text-cyan">
              {w}
            </span>
          ))}
        </div>
        <input
          value={witnessInput}
          onChange={(e) => setWitnessInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && witnessInput.trim()) {
              setWitnesses((w) => [...w, witnessInput.trim()]);
              setWitnessInput("");
            }
          }}
          placeholder="Witness name, press Enter"
          className="w-full border-b border-border bg-transparent px-1 py-2 font-mono text-sm outline-none focus:border-cyan"
        />
      </div>

      <button
        disabled={!file || uploading}
        onClick={submit}
        className="border border-crimson px-8 py-2 font-mono text-xs tracking-widest text-crimson hover:bg-crimson hover:text-black disabled:opacity-30"
      >
        {uploading ? "INGESTING…" : "INGEST EVIDENCE"}
      </button>

      <div>
        <h3 className="mb-3 font-mono text-xs uppercase tracking-widest text-muted">
          Evidence Manifest ({manifest.items?.length || 0})
        </h3>
        <table className="data-table w-full">
          <thead>
            <tr>
              <th>Filename</th>
              <th>SHA256</th>
              <th>Size</th>
              <th>Officer</th>
              <th>Timestamp</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {(manifest.items || []).map((item) => (
              <tr key={item.item_id}>
                <td>{item.filename}</td>
                <td className="max-w-[160px] truncate">{item.sha256}</td>
                <td>{(item.file_size_bytes / 1024 / 1024).toFixed(2)} MB</td>
                <td>{item.ingested_by}</td>
                <td>{item.ingested_at}</td>
                <td>
                  <input
                    type="file"
                    id={`verify-${item.item_id}`}
                    className="hidden"
                    onChange={(e) => e.target.files?.[0] && verify(item, e.target.files[0])}
                  />
                  <label
                    htmlFor={`verify-${item.item_id}`}
                    className="flex cursor-pointer items-center gap-1 text-muted hover:text-ink"
                    title="Pick the original file to re-hash and compare"
                  >
                    {verifyState[item.item_id] === "ok" && <CheckCircle2 size={13} className="text-neon" />}
                    {verifyState[item.item_id] === "mismatch" && <XCircle size={13} className="text-alarm" />}
                    {(!verifyState[item.item_id] || verifyState[item.item_id] === "checking") && (
                      <span className="font-mono text-[10px]">
                        {verifyState[item.item_id] === "checking" ? "checking…" : "verify"}
                      </span>
                    )}
                  </label>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
