# Verification: v0.2.0

The separate security-testing-support skill now includes real open-source scanner workflows, not only coordination guidance.

## Executed

- Semgrep Community Edition 1.185.0 installed from PyPI into an isolated temporary environment. Ran the packaged local demo runner with metrics/version checks disabled, no inherited token and two local rules. Exit 0; two intended alerts in the unsafe fictional source; no scanner errors; no alerts in the negative source. The unsafe source was never executed.
- ZAP 2.17.0 official Linux package downloaded and SHA-256 verified against the official release metadata (`efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a`). Ran the packaged native fixed-loopback demo with a 180-second enforced process-group timeout. Spider and passive analysis completed; exit 0 and four header-related alert categories. No active attack scan. The package's bundled add-ons were used without updating; ZAP warned they may be out of date.
- `evidence/scan-summary.json` contains a derived summary and raw-report hashes. This is evidence of scanner integration on fictional fixtures, not exploitability or real-product security.
- 52 Python unit tests passed, CLI examples ran, and skill frontmatter validation passed. Negative tests cover invalid evidence/closure, expired acceptance, malformed numeric input, unsupported report formats, omitted sensitive message content and authorization gating.

## Corrections during development

Original ledger review found a whitespace-owner gap and unbound risk acceptance; both fixed and retested. Initial native ZAP plan included a global maxDuration parameter unsupported by its bundled automation add-on. Removed it; retained job limits and external process timeout. The final scan succeeded without automation plan warnings.

## Not verified or claimed

No actual Mac installation, Docker Compose execution, private repository, authenticated application, real vulnerability validation, audit acceptance or compliance certification. No arbitrary public target or customer system was scanned. Demo rules and passive web checks are intentionally narrow, not comprehensive security coverage. Evidence references and approvals in a ledger remain user assertions, not independently authenticated. No publication or installation on the user's computer occurred.
