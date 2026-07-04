import { useEffect, useRef } from "react";
import { statusStreamUrl } from "./api";
import { useStore } from "./store";

/**
 * Opens a native EventSource against GET /api/v1/status/:id and routes each
 * event by its `type` field:
 *   - "pipeline_status": stage snapshot -> applyPipelineStatus + per-stage
 *     artifact counters
 *   - anything else (network_event, crypto_event, sms_event, clipboard_event,
 *     accessibility_event, permission_request, monkey_event, sandbox_stage,
 *     sandbox_complete): live sandbox event -> handleSandboxEvent
 * No polling — the whole UI updates purely from this one stream.
 */
export function useAnalysisStream(analysisId) {
  const applyPipelineStatus = useStore((s) => s.applyPipelineStatus);
  const applyStageArtifacts = useStore((s) => s.applyStageArtifacts);
  const handleSandboxEvent = useStore((s) => s.handleSandboxEvent);
  const pushTerminalLine = useStore((s) => s.pushTerminalLine);
  const openCriticalAlert = useStore((s) => s.openCriticalAlert);
  const sourceRef = useRef(null);

  useEffect(() => {
    if (!analysisId) return undefined;

    const es = new EventSource(statusStreamUrl(analysisId));
    sourceRef.current = es;

    es.onmessage = (msg) => {
      let evt;
      try {
        evt = JSON.parse(msg.data);
      } catch {
        return;
      }

      if (evt.type === "pipeline_status") {
        applyPipelineStatus(evt);
        Object.entries(evt.stages || {}).forEach(([name, sr]) => {
          if (sr.status === "done") applyStageArtifacts(name, sr.artifacts);
        });
        pushTerminalLine({
          ts: Date.now(),
          stage: evt.current_stage,
          text: `stage=${evt.current_stage} risk=${evt.risk_score ?? "--"} tier=${evt.risk_tier ?? "--"}`,
        });
        if (evt.risk_tier === "CRITICAL") openCriticalAlert();
        if (evt.current_stage === "COMPLETE" || evt.current_stage === "FAILED") {
          es.close();
        }
        return;
      }

      if (evt.type === "error") {
        pushTerminalLine({ ts: Date.now(), stage: "ERROR", text: evt.data?.error || "stream error" });
        es.close();
        return;
      }

      // Everything else is a live sandbox event.
      handleSandboxEvent(evt);
      pushTerminalLine({
        ts: Date.now(),
        stage: evt.type,
        text: describeSandboxEvent(evt),
      });
    };

    es.onerror = () => {
      // EventSource auto-retries; nothing to do unless the server closed it.
    };

    return () => {
      es.close();
      sourceRef.current = null;
    };
  }, [analysisId]); // eslint-disable-line react-hooks/exhaustive-deps
}

function describeSandboxEvent(evt) {
  const { type, data } = evt;
  switch (type) {
    case "network_event":
      return `NET ${data?.method || ""} ${data?.url || data?.host || ""}`;
    case "crypto_event":
      return `CRYPTO ${data?.algorithm || data?.type || ""}`;
    case "sms_event":
      return `SMS ${data?.type || ""}`;
    case "clipboard_event":
      return `CLIPBOARD ${data?.type || ""}`;
    case "accessibility_event":
      return `ACCESSIBILITY ${data?.type || ""}`;
    case "permission_request":
      return `PERMISSION_REQUEST ${(data?.permissions || []).join(", ")}`;
    case "monkey_event":
      return `MONKEY ${data?.action || ""}`;
    case "sandbox_stage":
      return `${data?.stage}: ${data?.action}`;
    case "sandbox_complete":
      return `DYNAMIC ANALYSIS COMPLETE — ${data?.artifact_count ?? 0} artifacts`;
    default:
      return type;
  }
}
