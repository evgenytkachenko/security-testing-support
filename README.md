# Security Testing Support

Version 0.2.0: a separate agent skill for authorized security testing, scanner evidence review, and remediation coordination.

## Start

Load [SKILL.md](SKILL.md) in your agent. Follow the [scanner guide](references/scanners.md) for Semgrep Community Edition and ZAP local demos, or [usage](references/usage.md) for offline findings review. Python 3.10+ is required for the helpers. Scanner installation requirements and Mac instructions are in the scanner guide.

## Included

- Fixed-scope fictional source and web fixtures with Semgrep CE and ZAP workflows.
- Sanitized report inventories, evidence-ledger checks, and remediation/audit guidance.
- Explicit authorization, scope, and timeout controls. No automatic arbitrary-target scanning.

## Verification

52 Python tests passed. Semgrep CE 1.185.0 found two intended issues in the unsafe fictional source, with zero scanner errors. ZAP 2.17.0 completed a localhost spider/passive-analysis/report run with four header-related alert categories. These were actual Linux runs, not proof of real-product security.

Mac installation, Docker Compose execution, authenticated targets, and active attack scanning were not tested. No customer or arbitrary public site was scanned. See [VERIFICATION.md](VERIFICATION.md) for limitations and evidence.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

Only test systems you own or are explicitly authorized to test. A clean scanner report does not establish security or compliance.
