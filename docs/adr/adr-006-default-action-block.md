# ADR-006: Default action is `block`

**Options:**
- `block`: replace the output with a notice;
- `annotate`: "spotlighting": mark the output as untrusted data and tell
  the model not to follow instructions in it (Hines et al., 2024,
  arXiv:2403.14720);
- `log`.

**Decision:** `block` by default; `annotate` and `log` are available.
**Why:** `annotate` depends on the model obeying the marking, which is the
very thing the attack exploits. `block` doesn't depend on the model.
**Cost:** a false positive costs a whole tool output, so the normal-suite
pass rate through the gateway is measured.
**Measurement:** `annotate` is measured only if the model budget allows a
fourth configuration.

Part of the [architecture decisions](README.md) (Phase 5).
