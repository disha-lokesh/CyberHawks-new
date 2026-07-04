import { create } from "zustand";

const PIPELINE_STAGES = [
  "STATIC_TRIAGE",
  "DYNAMIC_ANALYSIS",
  "CLOUD_C2_DETECTION",
  "NEO4J_GRAPH",
  "LLM_NARRATIVE",
  "PDF_GENERATION",
  "JARM_PROBE",
];

export const useStore = create((set, get) => ({
  // ── Case / job identity ────────────────────────────────────────────────
  caseId: null,
  caseMetadata: null,
  analysisId: null,
  apkMeta: null, // {filename, sha256, size}

  setCaseId: (caseId) => set({ caseId }),
  setCaseMetadata: (caseMetadata) => set({ caseMetadata, caseId: caseMetadata?.case_id }),
  setAnalysisId: (analysisId) => set({ analysisId }),
  setApkMeta: (apkMeta) => set({ apkMeta }),

  // ── Live pipeline status ───────────────────────────────────────────────
  currentStage: null,
  riskScore: null,
  riskTier: null,
  stages: {},

  applyPipelineStatus: (evt) =>
    set({
      currentStage: evt.current_stage,
      riskScore: evt.risk_score,
      riskTier: evt.risk_tier,
      stages: evt.stages || {},
    }),

  // ── Live metrics (accumulated from stage artifacts) ────────────────────
  iocCount: 0,
  yaraMatchCount: 0,
  indiaMatchCount: 0,
  ramPercent: 0,

  applyStageArtifacts: (stageName, artifacts) => {
    if (!artifacts) return;
    set((s) => ({
      iocCount: artifacts.ioc_count ?? s.iocCount,
      yaraMatchCount: artifacts.yara_categories?.length ?? s.yaraMatchCount,
      indiaMatchCount: artifacts.india_match_count ?? s.indiaMatchCount,
    }));
  },

  // ── Sandbox visualizer live event log ──────────────────────────────────
  sandboxActive: false,
  sandboxEvents: [], // full ordered log, for replay scrubbing
  hookCounts: { network: 0, crypto: 0, sms: 0, clipboard: 0, accessibility: 0, permission: 0 },
  lastSandboxEvent: null,
  forcedPermissions: [],
  monkeyTaps: [],
  syscallFreq: {},

  handleSandboxEvent: (evt) => {
    const { type, data } = evt;
    set((s) => {
      const next = { lastSandboxEvent: evt, sandboxEvents: [...s.sandboxEvents, evt] };

      if (type === "sandbox_stage" && data?.stage === "DYNAMIC_AVD_BOOT") {
        next.sandboxActive = true;
      }
      if (type === "sandbox_complete") {
        next.sandboxActive = false;
      }
      if (type.endsWith("_event") && type !== "monkey_event" && type !== "sandbox_stage") {
        const bucket = type.replace("_event", "");
        if (bucket in s.hookCounts) {
          next.hookCounts = { ...s.hookCounts, [bucket]: s.hookCounts[bucket] + 1 };
        }
      }
      if (type === "permission_request") {
        next.hookCounts = { ...s.hookCounts, permission: s.hookCounts.permission + 1 };
        const perms = data?.permissions || [];
        next.forcedPermissions = [...s.forcedPermissions, ...perms];
      }
      if (type === "monkey_event") {
        next.monkeyTaps = [...s.monkeyTaps.slice(-19), data];
      }
      return next;
    });
  },

  resetSandbox: () =>
    set({
      sandboxActive: false,
      sandboxEvents: [],
      hookCounts: { network: 0, crypto: 0, sms: 0, clipboard: 0, accessibility: 0, permission: 0 },
      lastSandboxEvent: null,
      forcedPermissions: [],
      monkeyTaps: [],
    }),

  // ── Terminal feed (raw event log for the scrolling console) ────────────
  terminalLines: [],
  pushTerminalLine: (line) =>
    set((s) => ({ terminalLines: [...s.terminalLines.slice(-499), line] })),

  // ── Toasts / critical alert ─────────────────────────────────────────────
  toasts: [],
  pushToast: (toast) =>
    set((s) => ({ toasts: [...s.toasts, { id: crypto.randomUUID(), ...toast }] })),
  dismissToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),

  criticalAlertOpen: false,
  openCriticalAlert: () => set({ criticalAlertOpen: true }),
  dismissCriticalAlert: () => set({ criticalAlertOpen: false }),

  // ── Reset for a fresh job ──────────────────────────────────────────────
  resetAnalysis: () =>
    set({
      currentStage: null,
      riskScore: null,
      riskTier: null,
      stages: {},
      iocCount: 0,
      yaraMatchCount: 0,
      indiaMatchCount: 0,
      terminalLines: [],
      sandboxActive: false,
      sandboxEvents: [],
      hookCounts: { network: 0, crypto: 0, sms: 0, clipboard: 0, accessibility: 0, permission: 0 },
      forcedPermissions: [],
      monkeyTaps: [],
      criticalAlertOpen: false,
    }),
}));

export { PIPELINE_STAGES };
