export const POLICY_META = {
  P1: {
    title: "Inbound hard safety",
    predicate: "hard_rules",
    phase: "request",
    category: "safety",
  },
  P2: {
    title: "Outbound hard safety",
    predicate: "hard_rules",
    phase: "response",
    category: "safety",
  },
  P3: {
    title: "Inbound constitution",
    predicate: "inbound_constitution",
    phase: "request",
    category: "constitution",
  },
  P4: {
    title: "Outbound constitution",
    predicate: "outbound_constitution",
    phase: "response",
    category: "constitution",
  },
  P5: {
    title: "Input token cap",
    predicate: "",
    phase: "request",
    category: "token budget",
  },
  P6: {
    title: "Output token cap",
    predicate: "",
    phase: "response",
    category: "token budget",
  },
  P7: {
    title: "Request rate limit",
    predicate: "",
    phase: "session",
    category: "rate limit",
  },
  P8: {
    title: "Session turn quota",
    predicate: "",
    phase: "session",
    category: "rate limit",
  },
  P9: {
    title: "Session token budget",
    predicate: "",
    phase: "session",
    category: "token budget",
  },
};

export const BUILTIN_POLICY_IDS = ["P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9"];
