# Validation Methodology

## Validation layers
1. **Syntax and metadata:** YAML parses, required fields exist, IDs are unique.
2. **Conversion:** the target backend converts the rule without unsupported constructs.
3. **Event tests:** synthetic positive and negative cases behave as expected.
4. **Replay:** representative authorized events are replayed in a lab.
5. **Operational review:** false-positive volume, performance, triage value, and ownership are assessed.
6. **Production monitoring:** staged rollout, change control, and rollback criteria are defined.

Passing one layer does not imply later layers passed. The local validator only covers layer 1. The JSON fixtures document test intent and are not automatically executed by a SIEM.
