async function request(path, options = {}) {
  const adminToken = adminTokenHeader();
  const response = await fetch(path, {
    ...options,
    headers: {
      "content-type": "application/json",
      ...adminToken,
      ...(options.headers || {}),
    },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.detail || payload.error || `${response.status} ${response.statusText}`);
  }
  return payload;
}

function adminTokenHeader() {
  const params = new URLSearchParams(window.location.search);
  const fromUrl = params.get("admin_token");
  if (fromUrl) {
    window.localStorage.setItem("enfguard_admin_token", fromUrl);
    return { "x-admin-token": fromUrl };
  }
  const stored = window.localStorage.getItem("enfguard_admin_token");
  return stored ? { "x-admin-token": stored } : {};
}

export function getPolicies() {
  return request("/admin/policies");
}

export function putPolicies(state) {
  return request("/admin/policies", {
    method: "PUT",
    body: JSON.stringify(state),
  });
}

export function reloadRuntime() {
  return request("/admin/reload", { method: "POST" });
}

export function upsertLivePolicy(policy) {
  return request("/admin/live_policy", {
    method: "POST",
    body: JSON.stringify(policy),
  });
}

export function deleteLivePolicy(policyId) {
  return request(`/admin/live_policy/${encodeURIComponent(policyId)}`, {
    method: "DELETE",
  });
}

export function setDryRun(enabled) {
  return request(`/admin/dryrun/${enabled ? "on" : "off"}`, { method: "POST" });
}

export function getTrace(tid) {
  return request(`/trace/${encodeURIComponent(tid)}?_=${Date.now()}`);
}

export function sendFeedback(tid, kind, payload) {
  return request("/feedback", {
    method: "POST",
    body: JSON.stringify({ tid, kind, payload }),
  });
}

export function overrideJudgeResult(payload) {
  return request("/admin/judge_override", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getTokenTotal(sid) {
  return request(`/admin/session/${encodeURIComponent(sid)}/tokens`);
}

export function getSwitches() {
  return request("/switches");
}

export function setSwitch(id, value) {
  return request(`/switches/${encodeURIComponent(id)}`, {
    method: "POST",
    body: JSON.stringify({ value }),
  });
}

export function listTraces(limit = 50) {
  return request(`/traces?limit=${encodeURIComponent(limit)}&_=${Date.now()}`);
}

export function getPendingApprovals() {
  return request("/pending_approvals");
}

export function resolveApproval(tid, decision, payload = "") {
  // Approval decisions reuse the /feedback endpoint with kind=approve|deny.
  return request("/feedback", {
    method: "POST",
    body: JSON.stringify({ tid, kind: decision, payload }),
  });
}
