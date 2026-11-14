# Real open-source scanning workflows

This extension uses **Semgrep Community Edition** for SAST and **ZAP** for a web baseline scan. These are real scanners, not model-created substitutes. Local demo authorization covers only the bundled fictional fixtures. It does not grant permission to scan arbitrary repositories or websites.

## 1. Semgrep CE on macOS

If Homebrew is installed, `brew install semgrep` installs the open-source CLI (Homebrew is maintained on a best-effort basis). Alternatively, with uv installed: `uv tool install semgrep`. Review installation permissions first. No Semgrep account or paid login is needed for this local demo. See https://github.com/semgrep/semgrep for official installation and licensing.

From this package folder:

```sh
python3 scripts/scanner_workflow.py run-sast-demo --authorize-local-demo --output ./sast-demo-output
python3 scripts/scanner_workflow.py semgrep-inventory ./sast-demo-output/semgrep.json
```

Use a fresh output folder. The runner scans only `demo/source` with the two bundled local Python rules. It disables metrics/version checks and uses an isolated home without inherited Semgrep tokens. It does **not execute the Python fixture**. The fixture deliberately contains `eval` and `shell=True`; do not import or run that source. Expect two narrow alerts and none in the negative fixture. These rules demonstrate integration; they are not a comprehensive SAST policy or interprocedural taint analysis.

For an owned/authorized real repository, agree the source scope, language/rules, exclusions and data handling first. Use organization-reviewed local rules and a specific checkout/build:

```sh
semgrep scan --config ./reviewed-local-rules.yml --metrics=off --disable-version-check --json --output ./semgrep-results.json ./authorized-source
```

The second command is a template, not executed by this package. Inspect raw output locally because it can contain source, paths and secrets. Do not use `--config auto`, remote rules, paid login or cloud upload by default. An exit code of zero does not mean no findings; inspect results, errors, skipped files, rules and coverage. Record scanner version and rule/config digest.

## 2. ZAP baseline on macOS with open-source container runtime

Use an existing supported Docker engine if installed. For an open-source Mac runtime, Homebrew can install Colima and Docker CLI/Compose:

```sh
brew install colima docker docker-compose
colima start --cpu 2 --memory 4
docker version
docker-compose version
```

Installation/startup changes your computer and may prompt for permissions. Follow the official Colima instructions: https://github.com/abiosoft/colima. Docker Desktop is an optional alternative with its own licensing; not required here.

The bundled Compose file runs a fictional read-only server and ZAP on an **internal-only network**, with no published host ports or external links. Images are fetched from official registries before the scan. Review image versions/digests; `stable` and `python:3.12-slim` are moving tags, not reproducible pins.

Run only after agreeing to scan the local fictional fixture:

```sh
mkdir ./zap-demo-output
export SCAN_OUTPUT="$(pwd)/zap-demo-output"
docker-compose -p security-skill-demo -f demo/compose.yml pull
docker-compose -p security-skill-demo -f demo/compose.yml up --abort-on-container-exit --exit-code-from zap
# Save the exit code immediately; 2 commonly means warnings, not tool failure.
scan_exit=$?
printf '%s\n' "$scan_exit" > "$SCAN_OUTPUT/exit-code.txt"
docker-compose -p security-skill-demo -f demo/compose.yml down
python3 scripts/scanner_workflow.py zap-inventory "$SCAN_OUTPUT/zap.json"
```

If your installation uses the Compose plugin, replace `docker-compose` with `docker compose`. If the ZAP user cannot write the bind mount, fix only the dedicated output folder ownership according to your local container runtime, not broad filesystem permissions. Stop on errors rather than declaring a clean scan.

ZAP baseline **actively crawls** pages for a bounded period and then analyzes responses with passive rules. It sends requests and is not network-passive or inherently safe for production. This demo has no mutating endpoints, authentication or customer data. The baseline is not ZAP's full active attack scan. Do not substitute `zap-full-scan.py`, change to a public target or add attack rules without separate bounded authorization.

ZAP baseline exit semantics: 0 success, 1 configured FAIL alerts, 2 warnings without FAIL, 3 other failure. Also inspect startup/scan logs and missing/truncated reports. A JSON report alone does not prove a complete scan. Keep exit code, tool version, image digest, scope/config and logs beside the report. See https://www.zaproxy.org/docs/docker/baseline-scan/.

## 3. Turning results into decisions

`semgrep-inventory` and `zap-inventory` omit raw messages, URLs and source snippets, retaining record indices/hashes and scanner labels. Manually map sanitized records into the ledger from `references/usage.md`. The tool does not infer exploitability, business severity, false positives, remediation or compliance. Use `references/validation.md` to plan verification with Security. Do not automatically mark an alert resolved because the next scan lacks it.

The inventory commands are limited adapters, not full scanner-format validators. They never read referenced artifacts or execute report text. Model analysis can organize findings and suggest questions; deterministic scanner evidence and human Security review remain authoritative.

## Native ZAP alternative (no Docker)

Download ZAP from https://www.zaproxy.org/download/ and verify its published checksum. Use a trusted official installation; the package does not download or install ZAP. The Mac installer includes Java; the cross-platform/Linux release requires Java 17+. Locate `zap.sh` inside the installed distribution, then run:

```sh
python3 scripts/run_zap_demo.py --zap /absolute/path/to/official/ZAP/zap.sh --output ./zap-native-output --authorize-local-demo
python3 scripts/scanner_workflow.py zap-inventory ./zap-native-output/zap.json
```

The native runner starts the supplied fictional server on an ephemeral **127.0.0.1-only** port, generates a fixed spider/passive-analysis/report plan, disables update checks, uses a temporary ZAP home and stops the process group after 180 seconds. It takes no target URL argument. It never runs an activeScan job or the unsafe Python SAST fixture. It shuts down the server afterward. Unlike the Docker demo it is not a network sandbox: it relies on a controlled fixture with no external URLs plus a constrained scan context. Do not replace the fixture with untrusted content.

Native Automation Framework exit codes are not the Docker baseline alert policy codes: inspect `receipt.json`, `run.log` and the generated report. A zero exit means the plan ran without reported execution problems, not that no alerts exist. Scanner/version/add-on behavior changes, so rerun after upgrades. The tested native Linux run does not establish that the Mac installation or Docker variant works.
