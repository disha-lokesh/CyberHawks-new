import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { generateJarmQr, importJarmQr, getStaticResult } from "../lib/api.js";
import { useStore } from "../lib/store.js";

export default function JarmBridge() {
  return (
    <div className="grid h-[calc(100vh-52px)] grid-cols-2 divide-x divide-border">
      <WorkstationA />
      <WorkstationB />
    </div>
  );
}

function WorkstationA() {
  const analysisId = useStore((s) => s.analysisId);
  const [ips, setIps] = useState([]);
  const [checked, setChecked] = useState(new Set());
  const [qr, setQr] = useState(null);
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    if (!analysisId) return;
    getStaticResult(analysisId)
      .then((r) => {
        const found = (r.data.iocs || []).filter((i) => i.ioc_type === "IP").map((i) => i.value);
        setIps(found);
        setChecked(new Set(found));
      })
      .catch(() => {});
  }, [analysisId]);

  useEffect(() => {
    if (!qr) return;
    setElapsed(0);
    const id = setInterval(() => setElapsed((e) => e + 1), 1000);
    return () => clearInterval(id);
  }, [qr]);

  async function generate() {
    if (!analysisId) return;
    const { data } = await generateJarmQr(analysisId);
    setQr(data);
  }

  return (
    <div className="flex flex-col items-center gap-5 overflow-y-auto p-8">
      <h2 className="font-mono text-sm tracking-widest text-crimson">
        GENERATE QR FOR WORKSTATION B
      </h2>

      <div className="w-full max-w-sm space-y-1">
        {ips.map((ip) => (
          <label key={ip} className="flex items-center gap-2 font-mono text-xs text-ink">
            <input
              type="checkbox"
              checked={checked.has(ip)}
              onChange={(e) =>
                setChecked((prev) => {
                  const next = new Set(prev);
                  e.target.checked ? next.add(ip) : next.delete(ip);
                  return next;
                })
              }
            />
            {ip}
          </label>
        ))}
        {ips.length === 0 && <div className="font-mono text-xs text-muted">No IP IOCs extracted yet.</div>}
      </div>

      <button
        onClick={generate}
        disabled={!analysisId}
        className="border border-crimson px-8 py-2 font-mono text-xs tracking-widest text-crimson hover:bg-crimson hover:text-black disabled:opacity-30"
      >
        GENERATE QR
      </button>

      {qr && (
        <div className="flex flex-col items-center gap-3">
          <div className="border-4 border-crimson p-3 shadow-glowCrimson">
            <img src={`data:image/png;base64,${qr.qr_image_b64}`} alt="JARM transfer QR" width={220} height={220} />
          </div>
          <div className="break-all font-mono text-[10px] text-amber">{qr.payload_hash}</div>
          <div className="font-mono text-[10px] text-muted">
            {qr.ip_count} IPs encoded · displayed {elapsed}s
          </div>
        </div>
      )}
    </div>
  );
}

function WorkstationB() {
  const analysisId = useStore((s) => s.analysisId);
  const navigate = useNavigate();
  const videoRef = useRef(null);
  const [scanning, setScanning] = useState(false);
  const [manualPayload, setManualPayload] = useState("");
  const [results, setResults] = useState(null);
  const [flash, setFlash] = useState(false);
  const [error, setError] = useState(null);
  const [detectorSupported] = useState(() => "BarcodeDetector" in window);

  useEffect(() => {
    let stream;
    let raf;
    let detector;

    async function start() {
      try {
        stream = await navigator.mediaDevices.getUserMedia({ video: true });
        if (videoRef.current) videoRef.current.srcObject = stream;
        setScanning(true);

        if (detectorSupported) {
          detector = new window.BarcodeDetector({ formats: ["qr_code"] });
          const tick = async () => {
            if (videoRef.current && videoRef.current.readyState === 4) {
              try {
                const codes = await detector.detect(videoRef.current);
                if (codes[0]) await handlePayload(codes[0].rawValue);
              } catch {
                /* detection frame miss — retry next tick */
              }
            }
            raf = requestAnimationFrame(tick);
          };
          raf = requestAnimationFrame(tick);
        }
      } catch (e) {
        setError("Camera access denied or unavailable — use manual paste below.");
      }
    }
    start();
    return () => {
      cancelAnimationFrame(raf);
      stream?.getTracks().forEach((t) => t.stop());
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  async function handlePayload(payload) {
    if (!analysisId) return;
    try {
      const { data } = await importJarmQr(payload, analysisId);
      setResults(data.jarm_results);
      setFlash(true);
      setTimeout(() => setFlash(false), 500);
    } catch (e) {
      setError(e?.response?.data?.detail || "QR validation failed — tampered or corrupt payload.");
    }
  }

  return (
    <div className="flex flex-col items-center gap-5 overflow-y-auto p-8">
      <h2 className="font-mono text-sm tracking-widest text-cyan">IMPORT JARM RESULTS</h2>

      <div className="relative h-56 w-56 overflow-hidden border-2 border-cyan bg-black">
        <video ref={videoRef} autoPlay muted playsInline className="h-full w-full object-cover" />
        {scanning && (
          <div className="pointer-events-none absolute inset-x-0 h-0.5 animate-scanline bg-crimson shadow-glowCrimson" />
        )}
        {flash && <div className="absolute inset-0 bg-neon/40" />}
      </div>
      {!detectorSupported && (
        <div className="max-w-xs text-center font-mono text-[10px] text-muted">
          This browser has no native QR detector — paste the scanned payload manually below.
        </div>
      )}
      {error && <div className="font-mono text-[10px] text-alarm">{error}</div>}

      <div className="w-full max-w-sm">
        <textarea
          value={manualPayload}
          onChange={(e) => setManualPayload(e.target.value)}
          placeholder="Paste QR payload JSON here…"
          rows={3}
          className="w-full border border-border bg-transparent p-2 font-mono text-[10px] text-ink outline-none focus:border-cyan"
        />
        <button
          onClick={() => handlePayload(manualPayload)}
          className="mt-2 w-full border border-cyan py-1.5 font-mono text-[10px] tracking-widest text-cyan hover:bg-cyan hover:text-black"
        >
          IMPORT PAYLOAD
        </button>
      </div>

      {results && (
        <div className="w-full max-w-sm space-y-2">
          <table className="data-table w-full">
            <thead>
              <tr>
                <th>Host</th>
                <th>JARM Hash</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r, i) => (
                <tr key={i}>
                  <td>{r.host}</td>
                  <td className="break-all text-amber">{r.jarm_hash}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <button
            onClick={() => navigate(`/report/${analysisId}`)}
            className="w-full border border-neon py-2 font-mono text-xs tracking-widest text-neon hover:bg-neon hover:text-black"
          >
            IMPORT TO REPORT
          </button>
        </div>
      )}
    </div>
  );
}
