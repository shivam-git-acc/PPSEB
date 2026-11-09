// The pinned, known-good demo run, served by Vite as a static file (not bundled
// into the JS). Used only when the backend cannot be reached (R13.11).
import goldenTraceUrl from "../../backend/results/demo_trace.json?url";

const BASE = "/api";

// Same envelope shape as the API, so the Demo tab cannot tell the sources apart
// except through the replayed_source / replayed_from fields it displays.
async function staticDemoTrace(backendError) {
  const res = await fetch(goldenTraceUrl);
  if (!res.ok) throw new Error(`backend unreachable (${backendError}) and no bundled trace`);
  const report = await res.json();
  return {
    result: {
      ...report,
      replayed: true,
      replayed_source: "bundled",
      replayed_from: "the copy bundled with the UI (backend/results/demo_trace.json at build time)",
      backend_error: backendError,
    },
    trace: [],
  };
}

async function post(path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = data?.detail ? JSON.stringify(data.detail) : data?.error || res.statusText;
    throw new Error(msg);
  }
  return data;
}

async function get(path, { timeoutMs } = {}) {
  // A hung backend must not hang the caller when it has a fallback (timeoutMs).
  const signal = timeoutMs ? AbortSignal.timeout(timeoutMs) : undefined;
  const res = await fetch(`${BASE}${path}`, { signal });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || data?.detail || res.statusText || `HTTP ${res.status}`);
  return data;
}

export const api = {
  health: () => get("/health"),
  init: (params) => post("/init", params),
  keyext: (periods) => post("/keyext", { periods }),
  encryptSearch: (body) => post("/encrypt-search", body),
  attackKga: (body) => post("/attack/kga", body),
  attackForward: (body) => post("/attack/forward", body),
  attackForwardSweep: (body) => post("/attack/forward-sweep", body),
  attackForwardFairness: (body) => post("/attack/forward-fairness", body),
  attackForwardE2E: (body) => post("/attack/forward-e2e", body),
  attackForwardE2EMulti: (body) => post("/attack/forward-e2e-multi", body),
  attackSpec: (body) => post("/attack/spec", body),

  sweepPreflight: (body) => post("/sweep/preflight", body),
  sweepStart: (body) => post("/sweep/start", body),
  sweepStatus: (jobId) => get(`/sweep/status?job_id=${encodeURIComponent(jobId)}`),
  sweepResults: (jobId, gate = "strict") => get(`/sweep/results?job_id=${encodeURIComponent(jobId)}&gate=${gate}`),
  sweepStop: (jobId) => post(`/sweep/stop?job_id=${encodeURIComponent(jobId)}`, {}),
  sweepJobs: () => get("/sweep/jobs"),
  nqSweepStart: (body) => post("/nq-sweep/start", body),
  nqSweepStatus: (jobId) => get(`/nq-sweep/status?job_id=${encodeURIComponent(jobId)}`),
  nqSweepJobs: () => get("/nq-sweep/jobs"),
  pkDemoRun: (body) => post("/pk-demo/run", body),
  boundaryStart: (body) => post("/boundary/start", body),
  boundaryStatus: (jobId) => get(`/boundary/status?job_id=${encodeURIComponent(jobId)}`),
  boundaryJobs: () => get("/boundary/jobs"),
  proofAnalysis: () => get("/proof/analysis"),
  ledgerRun: (body) => post("/ledger/run", body),
  recoveryStart: (body) => post("/recovery/start", body),
  recoveryStatus: (id) => get(`/recovery/status?job_id=${encodeURIComponent(id)}`),
  recoveryJobs: () => get("/recovery/jobs"),
  networkOptions: () => get("/network/options"),
  networkNew: (body) => post("/network/new", body),
  networkState: (id) => get(`/network/state?session_id=${encodeURIComponent(id)}`),
  networkRecord: (body) => post("/network/record", body),
  networkSearch: (body) => post("/network/search", body),
  networkAdvance: (body) => post("/network/advance", body),
  networkDecrypt: (body) => post("/network/decrypt", body),
  networkAttack: (body) => post("/network/attack", body),
  sweepExportUrl: (jobId, fmt) => `${BASE}/sweep/export?job_id=${encodeURIComponent(jobId)}&fmt=${fmt}`,

  /* ---- MedVault-PQ (patient-controlled sharing) ---- */
  mvSession: (body) => post("/medvault/session/new", body),
  mvState: () => get("/medvault/state"),
  mvUpload: (body) => post("/medvault/patient/upload", body),
  mvGrant: (body) => post("/medvault/patient/grant", body),
  mvRevoke: (body) => post("/medvault/patient/revoke", body),
  mvSearch: (body) => post("/medvault/doctor/search", body),
  mvRetrieve: (body) => post("/medvault/doctor/retrieve", body),
  mvEvilMode: (body) => post("/medvault/store/evil-mode", body),
  mvAudit: () => get("/medvault/audit/log"),
  mvAttack: (body) => post("/medvault/attack/run", body),
  mvTables: (full = false) => get(`/medvault/eval/tables?full=${full ? "true" : "false"}`),
  mvMeta: () => get("/medvault/system/meta"),
  mvDemo: (seed = 42) => post(`/medvault/system/demo-run?seed=${seed}`, {}),
  mvDemoTrace: async () => {
    try {
      return await get("/medvault/system/demo-trace?source=golden", { timeoutMs: 5000 });
    } catch (e) {
      return staticDemoTrace(String(e.message || e));
    }
  },
  mvZk: () => get("/medvault/zk/status"),
  mvTree: (body) => post("/medvault/tree/advance", body),
  mvChain: () => get("/medvault/chain/status"),
  mvTreePlotUrl: () => `${BASE}/medvault/tree/plot`,
};
