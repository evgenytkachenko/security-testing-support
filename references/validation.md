# Validation and remediation

Prepare a finding packet with scanner/run ID, rule, affected build, sanitized location, observable behavior, expected security property, prerequisites, evidence references, observed impact, unknowns, suggested owner and validation plan. Do not include live secrets or exploit payloads in customer-facing material.

For a SAST alert, ask whether input is attacker-controlled, whether the path is reachable, which trust boundary is crossed, and which existing controls apply. Review source and configuration if authorized; do not label the issue a false positive merely because the model cannot trace a path.

For a DAST alert, retain sanitized request/response evidence and tested role/environment. Separate a scanner's signature from reproduced security impact. Plan minimal non-destructive verification in a disposable environment with synthetic records. If the plan would access others' data, modify a shared target, increase privileges or run an unexpected exploit, stop and obtain an appropriately scoped Security-led authorization. This skill's helper executes no tests.

State meanings:
- untriaged: imported or reported, not validated.
- validating: owner investigating, outcome unknown.
- confirmed: validation evidence supports the finding.
- remediating: engineering addressing a confirmed issue.
- ready_for_retest: fix reference exists; not yet verified.
- closed_verified: reviewer records passed retest and evidence against the ledger's target build.
- false_positive: reviewer documents a reason and supporting evidence, not just a suppression.
- risk_accepted: authorized decision with scope, evidence, approval date and expiry; still not remediated.

Retest the original security property, negative cases and relevant nearby behavior. Verify the fixed commit is deployed in the tested environment. Maintain a regression test where feasible. A fix commit, ticket closure, suppression, baseline `absent` flag or clean scan is not sufficient by itself. Reopen findings when evidence contradicts closure or the affected condition returns. The helper validates snapshots; it does not maintain history. Preserve successive dated records in your approved tracker/versioned evidence store.
