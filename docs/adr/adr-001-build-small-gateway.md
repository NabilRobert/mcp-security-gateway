# ADR-001: Build a small gateway instead of adopting one

**Context:** good gateways already exist. Checked 2026-10-26 on GitHub and
PyPI:

| Gateway | Licence | Activity |
|---|---|---|
| IBM ContextForge | Apache-2.0 | about 4.7k stars, pushed 2026-10-25 |
| Docker MCP Gateway | MIT | about 1.6k stars, pushed 2026-10-26 |
| Microsoft MCP Gateway | MIT | about 900 stars, pushed 2026-10-21 |
| Enkrypt Secure MCP Gateway | Apache-2.0 | pushed 2026-10-22 |
| mcpgw | MIT | 0.1.0 |

**Options:**
- (a) adopt one and contribute;
- (b) build a small one;
- (c) both: build a small one, and later run the same attack suite against
  one of the above.

**Decision:** (b) now, (c) as a *could*.
**Why:** the portfolio needs code that a reviewer can read in about
15 minutes and that Arthur can defend line by line. The large gateways do
far more (registries, federation, UIs), and that would bury the part being
measured. The measurement is the contribution, and it works against any
gateway, so (c) stays open.
**Consequences:**
- The README says plainly that this isn't a production gateway and links
  the ones above.
- Feature claims about the other gateways are limited to what was checked
  (licence, activity, description), never their detection quality.

Part of the [architecture decisions](README.md) (Phase 5).
