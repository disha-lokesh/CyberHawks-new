import axios from "axios";

// In dev, Vite proxies /api/v1 -> http://localhost:8000 (see vite.config.js).
// In production, set VITE_API_BASE at build time if the backend isn't
// served from the same origin as the frontend.
const baseURL = import.meta.env.VITE_API_BASE || "/api/v1";

export const api = axios.create({ baseURL });

// ── Cases / Analysis (backend/api/analysis.py) ───────────────────────────────
export const createCase = (caseMetadata) => api.post("/cases", caseMetadata);

export const uploadApk = (caseId, file, onProgress) => {
  const form = new FormData();
  form.append("case_id", caseId);
  form.append("file", file);
  return api.post("/analyze", form, {
    headers: { "Content-Type": "multipart/form-data" },
    onUploadProgress: onProgress,
  });
};

export const getResult = (analysisId) => api.get(`/result/${analysisId}`);
export const getStaticResult = (analysisId) => api.get(`/result/${analysisId}/static`);
export const getDynamicResult = (analysisId) => api.get(`/result/${analysisId}/dynamic`);
export const getCustodyChain = (analysisId) => api.get(`/custody/${analysisId}`);
export const verifyCustodyChain = (analysisId) => api.get(`/custody/${analysisId}/verify`);

// SSE URL builder — consumed by useAnalysisStream (native EventSource, not axios)
export const statusStreamUrl = (analysisId) => `${baseURL}/status/${analysisId}`;

// ── Reports (backend/api/reports.py) ─────────────────────────────────────────
export const reportDownloadUrl = (analysisId) => `${baseURL}/report/${analysisId}/download`;
export const getReportCustody = (analysisId) => api.get(`/report/${analysisId}/custody`);
export const getEvidenceManifestForAnalysis = (analysisId) =>
  api.get(`/report/${analysisId}/manifest`);

// ── Graph (backend/api/graph.py) ─────────────────────────────────────────────
export const getIocGraph = (analysisId) => api.get(`/graph/${analysisId}`);
export const searchSyndicates = (params) => api.get("/graph/syndicate/search", { params });
export const getJarmSyndicate = (jarmHash) => api.get(`/graph/syndicate/jarm/${jarmHash}`);

// ── JARM (backend/api/jarm.py) ────────────────────────────────────────────────
export const runJarmProbe = (ips, analysisId) =>
  api.post("/jarm/probe", { ips, analysis_id: analysisId });
export const generateJarmQr = (analysisId) =>
  api.post("/jarm/qr/generate", null, { params: { analysis_id: analysisId } });
export const importJarmQr = (qrPayload, analysisId) =>
  api.post("/jarm/qr/import", { qr_payload: qrPayload, analysis_id: analysisId });
export const triggerCspSweep = (jarmHash) => api.get(`/jarm/sweep/${jarmHash}`);

// ── Evidence (backend/api/evidence.py) ───────────────────────────────────────
export const uploadEvidenceVideo = (payload, onProgress) => {
  const form = new FormData();
  Object.entries(payload).forEach(([k, v]) => {
    if (k !== "file") form.append(k, v);
  });
  form.append("file", payload.file);
  return api.post("/evidence/video", form, {
    headers: { "Content-Type": "multipart/form-data" },
    onUploadProgress: onProgress,
  });
};
export const getEvidenceManifest = (caseId) => api.get(`/evidence/${caseId}/manifest`);

export const getHealth = () => axios.get("/health", { baseURL: "" });
