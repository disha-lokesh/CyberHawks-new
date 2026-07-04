import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { Lock, UploadCloud, Fingerprint, CheckCircle2 } from "lucide-react";
import { WizardShell, Field } from "../components/wizard/WizardStep.jsx";
import { createCase, uploadEvidenceVideo } from "../lib/api.js";
import { sha256File } from "../lib/hash.js";
import { useStore } from "../lib/store.js";

const LABELS = ["Case", "Device", "Evidence", "Review", "Sign-off"];

const emptyOfficer = { officer_id: "", badge_id: "", name: "", rank: "", station: "", district: "" };

export default function CaseSetupWizard() {
  const navigate = useNavigate();
  const setCaseMetadata = useStore((s) => s.setCaseMetadata);
  const pushToast = useStore((s) => s.pushToast);
  const [step, setStep] = useState(1);
  const [submitting, setSubmitting] = useState(false);

  const [form, setForm] = useState({
    fir_number: "",
    district: "",
    station: "",
    reporting_officer: { ...emptyOfficer },
    reviewing_officer: { ...emptyOfficer },
    device: { imei: "", make: "", model: "", android_version: "", serial_number: "" },
    seizure_gps_lat: null,
    seizure_gps_lon: null,
    seizure_witnesses: [],
  });
  const [videoFile, setVideoFile] = useState(null);
  const [videoHash, setVideoHash] = useState(null);
  const [witnessInput, setWitnessInput] = useState("");
  const [signed, setSigned] = useState({ reporting: false, reviewing: false });

  const update = (path, value) =>
    setForm((f) => {
      const next = structuredClone(f);
      const keys = path.split(".");
      let obj = next;
      for (let i = 0; i < keys.length - 1; i++) obj = obj[keys[i]];
      obj[keys[keys.length - 1]] = value;
      return next;
    });

  const next = () => setStep((s) => Math.min(5, s + 1));
  const back = () => setStep((s) => Math.max(1, s - 1));

  async function handleVideoDrop(file) {
    setVideoFile(file);
    const hash = await sha256File(file);
    setVideoHash(hash);
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (pos) => {
          update("seizure_gps_lat", pos.coords.latitude);
          update("seizure_gps_lon", pos.coords.longitude);
        },
        () => {},
        { timeout: 5000 }
      );
    }
  }

  async function finalize() {
    setSubmitting(true);
    try {
      const payload = { ...form, seizure_video_hash: videoHash || undefined };
      const { data } = await createCase(payload);
      const caseId = data.case_id;
      setCaseMetadata({ ...payload, case_id: caseId });

      if (videoFile) {
        await uploadEvidenceVideo({
          case_id: caseId,
          officer_badge: form.reporting_officer.badge_id,
          gps_lat: form.seizure_gps_lat || 0,
          gps_lon: form.seizure_gps_lon || 0,
          witnesses: form.seizure_witnesses.join(","),
          file: videoFile,
        });
      }

      pushToast({ variant: "success", title: "Case registered", message: `Case ${caseId.slice(0, 8)} locked` });
      navigate("/upload");
    } catch (err) {
      pushToast({
        variant: "warning",
        title: "Case registration failed",
        message: err?.response?.data?.detail || err.message,
      });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <WizardShell step={step} totalSteps={5} labels={LABELS}>
      {step === 1 && (
        <div className="space-y-5">
          <h2 className="font-mono text-lg text-ink">STEP 1 — CASE DETAILS</h2>
          <div className="grid grid-cols-2 gap-5">
            <Field label="FIR Number" value={form.fir_number} onChange={(e) => update("fir_number", e.target.value)} />
            <Field label="District" value={form.district} onChange={(e) => update("district", e.target.value)} />
            <Field label="Station" value={form.station} onChange={(e) => update("station", e.target.value)} />
          </div>
          <h3 className="mt-6 font-mono text-xs uppercase tracking-wider text-muted">Reporting Officer</h3>
          <OfficerFields officer={form.reporting_officer} onChange={(k, v) => update(`reporting_officer.${k}`, v)} />
          <h3 className="mt-6 font-mono text-xs uppercase tracking-wider text-muted">Reviewing Officer</h3>
          <OfficerFields officer={form.reviewing_officer} onChange={(k, v) => update(`reviewing_officer.${k}`, v)} />
          <StepNav onNext={next} />
        </div>
      )}

      {step === 2 && (
        <div className="space-y-5">
          <h2 className="font-mono text-lg text-ink">STEP 2 — DEVICE INFO</h2>
          <div className="grid grid-cols-2 gap-5">
            <Field
              label="IMEI"
              value={form.device.imei}
              onChange={(e) => update("device.imei", formatImei(e.target.value))}
              maxLength={17}
            />
            <Field label="Make" value={form.device.make} onChange={(e) => update("device.make", e.target.value)} />
            <Field label="Model" value={form.device.model} onChange={(e) => update("device.model", e.target.value)} />
            <Field
              label="Android Version"
              value={form.device.android_version}
              onChange={(e) => update("device.android_version", e.target.value)}
            />
          </div>
          <StepNav onBack={back} onNext={next} />
        </div>
      )}

      {step === 3 && (
        <div className="space-y-5">
          <h2 className="font-mono text-lg text-ink">STEP 3 — BNSS 176(3) EVIDENCE</h2>
          <DropZone file={videoFile} hash={videoHash} onDrop={handleVideoDrop} />
          <div className="grid grid-cols-2 gap-5 font-mono text-xs text-muted">
            <div>
              GPS:{" "}
              {form.seizure_gps_lat
                ? `${form.seizure_gps_lat.toFixed(5)}, ${form.seizure_gps_lon.toFixed(5)}`
                : "awaiting location permission…"}
            </div>
          </div>
          <div>
            <span className="mb-1 block font-mono text-[10px] uppercase tracking-wider text-muted">
              Witnesses
            </span>
            <div className="flex flex-wrap gap-2 mb-2">
              {form.seizure_witnesses.map((w, i) => (
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
                  update("seizure_witnesses", [...form.seizure_witnesses, witnessInput.trim()]);
                  setWitnessInput("");
                }
              }}
              placeholder="Type a name and press Enter"
              className="w-full border-b border-border bg-transparent px-1 py-2 font-mono text-sm outline-none focus:border-cyan"
            />
          </div>
          <StepNav onBack={back} onNext={next} />
        </div>
      )}

      {step === 4 && (
        <div className="space-y-5">
          <h2 className="font-mono text-lg text-ink">STEP 4 — REVIEW</h2>
          <ReviewGrid form={form} videoHash={videoHash} />
          <StepNav onBack={back} onNext={next} />
        </div>
      )}

      {step === 5 && (
        <div className="space-y-5">
          <h2 className="font-mono text-lg text-ink">STEP 5 — DUAL OFFICER SIGN-OFF</h2>
          <div className="grid grid-cols-2 gap-5">
            <SignaturePanel
              label="Reporting Officer"
              officer={form.reporting_officer}
              signed={signed.reporting}
              onSign={() => setSigned((s) => ({ ...s, reporting: true }))}
            />
            <SignaturePanel
              label="Reviewing Officer"
              officer={form.reviewing_officer}
              signed={signed.reviewing}
              onSign={() => setSigned((s) => ({ ...s, reviewing: true }))}
            />
          </div>
          <div className="flex justify-between pt-4">
            <button onClick={back} className="font-mono text-xs text-muted hover:text-ink">
              ← BACK
            </button>
            <button
              disabled={!signed.reporting || !signed.reviewing || submitting}
              onClick={finalize}
              className="border border-crimson px-6 py-2 font-mono text-xs tracking-widest text-crimson transition hover:bg-crimson hover:text-black disabled:opacity-30 disabled:hover:bg-transparent disabled:hover:text-crimson"
            >
              {submitting ? "REGISTERING…" : "COMPLETE CASE SETUP"}
            </button>
          </div>
        </div>
      )}
    </WizardShell>
  );
}

function formatImei(raw) {
  const digits = raw.replace(/\D/g, "").slice(0, 15);
  return digits.match(/.{1,4}/g)?.join("-") || digits;
}

function OfficerFields({ officer, onChange }) {
  return (
    <div className="grid grid-cols-3 gap-4">
      <Field label="Officer ID" value={officer.officer_id} onChange={(e) => onChange("officer_id", e.target.value)} />
      <Field label="Badge ID" value={officer.badge_id} onChange={(e) => onChange("badge_id", e.target.value)} />
      <Field label="Name" value={officer.name} onChange={(e) => onChange("name", e.target.value)} />
      <Field label="Rank" value={officer.rank} onChange={(e) => onChange("rank", e.target.value)} />
      <Field label="Station" value={officer.station} onChange={(e) => onChange("station", e.target.value)} />
      <Field label="District" value={officer.district} onChange={(e) => onChange("district", e.target.value)} />
    </div>
  );
}

function StepNav({ onBack, onNext }) {
  return (
    <div className="flex justify-between pt-4">
      {onBack ? (
        <button onClick={onBack} className="font-mono text-xs text-muted hover:text-ink">
          ← BACK
        </button>
      ) : (
        <span />
      )}
      <button
        onClick={onNext}
        className="border border-cyan px-6 py-2 font-mono text-xs tracking-widest text-cyan transition hover:bg-cyan hover:text-black"
      >
        CONTINUE →
      </button>
    </div>
  );
}

function DropZone({ file, hash, onDrop }) {
  const [dragging, setDragging] = useState(false);
  return (
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
        if (f) onDrop(f);
      }}
      className={`flex flex-col items-center justify-center gap-3 border-2 border-dashed p-10 text-center transition-colors ${
        dragging ? "border-crimson bg-crimson/5" : "border-border"
      }`}
    >
      <UploadCloud size={32} className={dragging ? "text-crimson" : "text-muted"} />
      <input
        type="file"
        accept="video/*"
        id="video-input"
        className="hidden"
        onChange={(e) => e.target.files?.[0] && onDrop(e.target.files[0])}
      />
      <label htmlFor="video-input" className="cursor-pointer font-mono text-xs text-muted">
        Drag seizure video here, or click to browse
      </label>
      {file && (
        <div className="mt-2 font-mono text-xs">
          <div className="text-ink">{file.name}</div>
          <div className="mt-1 break-all text-amber">{hash || "hashing…"}</div>
        </div>
      )}
    </div>
  );
}

function ReviewGrid({ form, videoHash }) {
  const rows = [
    ["FIR Number", form.fir_number],
    ["District / Station", `${form.district} / ${form.station}`],
    ["Reporting Officer", `${form.reporting_officer.name} (${form.reporting_officer.badge_id})`],
    ["Reviewing Officer", `${form.reviewing_officer.name} (${form.reviewing_officer.badge_id})`],
    ["Device", `${form.device.make} ${form.device.model} — ${form.device.imei}`],
    ["Witnesses", form.seizure_witnesses.join(", ") || "none"],
    ["Evidence SHA256", videoHash || "no video attached"],
  ];
  return (
    <div className="space-y-2">
      {rows.map(([label, value]) => (
        <div key={label} className="flex items-center justify-between border-b border-border/60 py-2">
          <span className="font-mono text-xs text-muted">{label}</span>
          <span className="flex items-center gap-2 font-mono text-xs text-ink">
            <Lock size={11} className="text-neon" />
            {value}
          </span>
        </div>
      ))}
    </div>
  );
}

function SignaturePanel({ label, officer, signed, onSign }) {
  const [scanning, setScanning] = useState(false);
  const doSign = () => {
    setScanning(true);
    setTimeout(() => {
      setScanning(false);
      onSign();
    }, 1100);
  };
  return (
    <div className="panel flex flex-col items-center gap-3 border border-border p-6">
      <span className="font-mono text-xs uppercase tracking-wider text-muted">{label}</span>
      <span className="font-mono text-sm text-ink">{officer.name || "—"}</span>
      <button
        disabled={signed}
        onClick={doSign}
        className={`relative flex h-16 w-16 items-center justify-center rounded-full border-2 transition-colors ${
          signed ? "border-neon" : "border-crimson"
        }`}
      >
        {scanning && (
          <motion.span
            className="absolute inset-0 rounded-full border-2 border-crimson"
            initial={{ scale: 0.6, opacity: 0.8 }}
            animate={{ scale: 1.8, opacity: 0 }}
            transition={{ duration: 0.8, repeat: 2 }}
          />
        )}
        {signed ? <CheckCircle2 className="text-neon" /> : <Fingerprint className="text-crimson" />}
      </button>
      {signed && (
        <span className="font-mono text-[10px] text-neon">SIGNED {new Date().toLocaleTimeString()}</span>
      )}
    </div>
  );
}
