const LIVE_POLICY_ID_PREFIX = "live_policy_";
const LIVE_POLICY_VALID_SCOPES = ["session", "persistent"];
const LIVE_POLICY_DEFAULT_SCOPE = "session";

function livePolicyTemplate(policyId) {
  const safeId = policyId || `${LIVE_POLICY_ID_PREFIX}1`;
  return `ALWAYS (FORALL t, c, n.
  (PolicyActive(t, "${safeId}")
   AND UserMessage(t, c, n)
   AND n > 40)
  IMPLIES BlockRequest(t, "live_policy", "live prompt token limit"))`;
}

function nextLivePolicyId(existing) {
  const taken = new Set(
    (Array.isArray(existing) ? existing : [])
      .map((policy) => (policy && policy.id) || "")
      .filter(Boolean),
  );
  for (let i = 1; i < 1000; i += 1) {
    const candidate = `${LIVE_POLICY_ID_PREFIX}${i}`;
    if (!taken.has(candidate)) return candidate;
  }
  return `${LIVE_POLICY_ID_PREFIX}${Date.now()}`;
}

export {
  LIVE_POLICY_ID_PREFIX,
  LIVE_POLICY_VALID_SCOPES,
  LIVE_POLICY_DEFAULT_SCOPE,
  livePolicyTemplate,
  nextLivePolicyId,
};
