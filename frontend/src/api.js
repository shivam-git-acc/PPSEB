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
};
