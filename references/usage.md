# Use and schema

Requires Python 3.10+; no third-party dependencies. Keep this folder intact. In Claude Code or Codex, load SKILL.md explicitly or place the folder in the host's documented skill directory. No host installation is performed by this package.

Run from this skill folder:

```sh
python3 scripts/security_review.py validate examples/ledger.json
python3 scripts/security_review.py report examples/ledger.json --as-of 2026-11-14
python3 scripts/security_review.py sarif-inventory examples/findings.sarif.json
python3 -m unittest discover -s tests -v
```

Commands read only the named local file and print JSON. Redirect stdout to a new output file if desired. Review and sanitize data locally before giving it to an AI model. The helper is not a general-purpose redaction tool. SARIF inventory avoids copying messages, paths, URLs or rule names; it does not remove the original input or guarantee that other manual outputs are sanitized.

## Ledger v1

See `examples/ledger.json` for a complete fictional record. Root: `schema_version: 1`, nonempty `product`, `target_build`, `scope.environment`, `scope.description`, and `findings` list. Every finding has a unique nonempty `id`, `title`, `source_ref`, `affected_build`, `source_type` (SAST/DAST/SCA/manual/other), `severity` (unknown/informational/low/medium/high/critical), `state` and optionally `due_date` in YYYY-MM-DD form.

All states other than untriaged/false_positive require `owner`. Confirmed/remediating/ready_for_retest/closed_verified require a nonempty `validation_evidence` string list. Ready_for_retest/closed_verified require `fix_ref`.

Closed_verified requires `retest`: `result: passed`, `build` equal to root target_build, nonempty `reviewer`, YYYY-MM-DD `date`, and nonempty `evidence` list. False_positive requires `reviewer`, `rationale`, and `decision_evidence`. Risk_accepted requires `acceptance`: `approver`, `rationale`, `scope`, `build` equal to root target_build, nonempty `approval_evidence`, `approved_on`, and `expires` after approval. Report flags acceptance expired on or before the explicit as-of date, and rejects future approval/retest evidence relative to that date.

The CLI checks nonempty references, not their existence or truth. It has no authority to approve risk or certify closure. Report output identifies attention items without awarding an overall security pass. Input capped at 5 MB. Duplicate JSON keys rejected. Keep backups/version history; no mutation or merge command exists.

## SARIF subset

Only embedded `runs[].results[]` in version 2.1.0 is supported. External property files are rejected and never fetched. Each result becomes an index and SHA-256 fingerprint with the scanner's level, unknown business severity and untriaged status. Suppression/baseline-absence are annotations, never closure. This is an inventory, not an automatic normalized ledger or full SARIF validator. Execution success remains `not_verified` unless explicit failure is present, because this helper does not establish scan coverage. Map safe titles and evidence references into a ledger manually; repeated imports do not merge or deduplicate across changed files/builds.

Risk acceptance is bound to the current target build in this first version. Re-review and document applicability when the build changes; do not automatically copy approval to a new build. Optional owner values, when supplied, must be nonempty strings.

## Scanner extension

For real Semgrep CE and ZAP workflows, see [scanners.md](scanners.md). The offline ledger commands still require only Python. Scanner demo dependencies are optional and installed separately.
