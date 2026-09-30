const BASE = "/api";

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

async function get(path) {
  const res = await fetch(`${BASE}${path}`);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || res.statusText);
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
};
