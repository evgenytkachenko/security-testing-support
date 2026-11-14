# Program and CI coordination

Build a scope matrix before proposing gates: application/build, repository/service owner, scan type, rule profile, authenticated roles, environment, frequency, exclusions, evidence retention and Security contact. SAST assesses code patterns; DAST exercises deployed behavior. Neither substitutes for architecture review or business-logic and authorization testing.

Use SAST in pull-request/build workflows and scoped DAST in a suitable isolated deployed environment where authorized. Full scans, baseline scans and changed-code scans have different coverage. Capture scanner failure, timeout, disabled rules and skipped jobs separately from finding counts. Never turn unavailable scans into a clean result.

Propose rather than impose release gates. Examples to discuss: new Security-confirmed high-risk findings, expired exceptions, missing required scan coverage, or remediation past an agreed SLA. Separate technical gate recommendations from the accountable release decision. Existing findings are not automatically acceptable; maintain a baseline with owners and review dates.

Suggested ownership: QE organizes scope, reproducible evidence and regressions; Security validates technical risk and approves test methods; Engineering fixes; Product schedules tradeoffs; authorized risk owners accept residual risk; Legal/Compliance approve external representations. Roles vary by organization: confirm names and decision authority.

Useful metrics: coverage by in-scope service and role; scan reliability; findings awaiting validation; time to validated triage; time to verified remediation; reopened findings; overdue work; expired exceptions. Record denominators and time periods. Scanner alert counts and dismissal rate alone are not risk reduction. Do not calculate a zero denominator as 0% risk.
