import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { ShieldAlert } from "lucide-react";
import { uploadApk } from "../lib/api.js";
import { sha256File } from "../lib/hash.js";
import { useStore } from "../lib/store.js";

export default function Upload() {
  const navigate = useNavigate();
  const caseId = useStore((s) => s.caseId);
  const setAnalysisId = useStore((s) => s.setAnalysisId);
  const setApkMeta = useStore((s) => s.setApkMeta);
  const resetAnalysis = useStore((s) => s.resetAnalysis);
  const pushToast = useStore((s) => s.pushToast);

  const [file, setFile] = useState(null);
  const [hash, setHash] = useState("");
  const [hashing, setHashing] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  async function handleFile(f) {
    if (!f.name.toLowerCase().endsWith(".apk")) {
      pushToast({ variant: "warning", message: "Only .apk files are accepted" });
      return;
    }
    setFile(f);
    setHash("");
    setHashing(true);
    const full = await sha256File(f);
    setHash(full);
    setHashing(false);
  }

  async function initiate() {
    if (!caseId) {
      pushToast({ variant: "warning", message: "Complete Case Setup first" });
      navigate("/setup");
      return;
    }
    setSubmitting(true);
    resetAnalysis();
    try {
      const { data } = await uploadApk(caseId, file);
      setAnalysisId(data.analysis_id);
      setApkMeta({ filename: data.filename, sha256: data.sha256, size: file.size });
      navigate(`/analysis/${data.analysis_id}`);
    } catch (err) {
      pushToast({
        variant: "warning",
        title: "Upload failed",
        message: err?.response?.data?.detail || err.message,
      });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="relative flex min-h-[calc(100vh-52px)] flex-col items-center justify-center overflow-hidden px-6">
      <EagleWatermark />

      {!caseId && (
        <div className="mb-6 flex items-center gap-2 border border-amber/50 bg-amber/5 px-4 py-2 font-mono text-xs text-amber">
          <ShieldAlert size={14} />
          No case registered — complete the Case Setup Wizard first.
        </div>
      )}

      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          const f = e.dataTransfer.files?.[0];
          if (f) handleFile(f);
        }}
        className="relative"
      >
        <input
          type="file"
          accept=".apk"
          id="apk-input"
          className="hidden"
          onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])}
        />
        <label
          htmlFor="apk-input"
          className={`relative flex h-64 w-64 cursor-pointer items-center justify-center transition-transform ${
            dragging ? "scale-105" : ""
          }`}
          style={{ clipPath: "polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)" }}
        >
          <div
            className={`absolute inset-0 border-2 border-dashed transition-all ${
              dragging ? "border-crimson shadow-glowCrimson" : "border-crimson/50"
            }`}
            style={{ clipPath: "polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)" }}
          />
          <div className="z-10 text-center font-mono text-xs text-muted">
            {file ? (
              <span className="text-ink">{file.name}</span>
            ) : (
              <span>DROP APK<br />OR CLICK</span>
            )}
          </div>
        </label>
      </div>

      <AnimatePresence>
        {file && (
          <motion.div
            initial={{ y: 20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: 20, opacity: 0 }}
            className="panel mt-8 w-full max-w-lg p-5"
          >
            <div className="grid grid-cols-2 gap-2 font-mono text-xs">
              <div className="text-muted">Filename</div>
              <div className="text-right text-ink">{file.name}</div>
              <div className="text-muted">Size</div>
              <div className="text-right text-ink">{(file.size / 1024 / 1024).toFixed(2)} MB</div>
              <div className="text-muted">SHA256</div>
              <div className="col-span-2 break-all text-right text-amber">
                {hashing ? <TypingHash /> : hash}
              </div>
            </div>
            <button
              disabled={hashing || submitting}
              onClick={initiate}
              className="group relative mt-5 w-full overflow-hidden border border-crimson py-3 font-mono text-xs tracking-widest text-crimson transition disabled:opacity-40"
            >
              <span className="relative z-10 group-hover:text-black">
                {submitting ? "STARTING PIPELINE…" : "INITIATE ANALYSIS"}
              </span>
              <span className="absolute inset-0 -translate-x-full bg-crimson transition-transform duration-300 group-hover:translate-x-0" />
            </button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function TypingHash() {
  return <span className="animate-pulse">computing sha256…</span>;
}

function EagleWatermark() {
  return (
    <svg
      className="pointer-events-none absolute inset-0 m-auto animate-[spin_60s_linear_infinite] opacity-[0.03]"
      width="500"
      height="500"
      viewBox="0 0 24 24"
    >
      <path d="M12 2 L3 9 L7 9 L4 20 L12 14 L20 20 L17 9 L21 9 Z" fill="#e94560" />
    </svg>
  );
}
