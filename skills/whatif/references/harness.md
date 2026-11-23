# Reviewed local harness campaigns · 3.2

Use this mode for Bastion CLI lifecycle questions: approval refusal, receipt reuse, changed inputs, foreign progress cursors, tampered reports and cancellation before work. For browser, backend or population questions use the existing corresponding modes; a CLI campaign is not a substitute for those tests.

Discover `whatif_harness_plan`, `whatif_harness_run` and `whatif_harness_verify`. If the loaded plugin lacks them, use the candidate CLI and clearly distinguish source execution from an installed-plugin upgrade.

Planning takes an absolute reviewed Bastion source directory, an explicit Python executable and a new case directory. It pins the Python modules, interpreter and WhatIF adapter; it does not execute them. Inspect `plan.json`, the fixed scenario list and the total command/output/wall budgets. Running requires the exact source acknowledgement and returned plan digest. This is trusted host-code execution with a reduced child environment and isolated Python import mode, not an OS sandbox or authorization for a production target.

```sh
node src/cli.mjs harness-plan --source ABSOLUTE_BASTION_SOURCE --python ABSOLUTE_PYTHON --out NEW_CASE
node src/cli.mjs harness-run --case CASE --ack-source EXACT_SOURCE --digest PLAN_DIGEST
node src/cli.mjs harness-verify --case CASE
```

The adapter creates only its owned fixtures, uses fixed command arguments without a shell, makes no HTTP/model calls, runs once per directory and stops after the first failing scenario. It retains bounded command responses plus hashes and coverage. A fresh verifier rechecks fixed assertions from retained responses; it does not merely trust the aggregate passed flag. Source changes require a new plan. A changed adapter requires its matching retained version for verification. Do not change the fixed oracles to obtain a pass.

Report planned, executed, passed, failed and unknown counts, command attempts and output budget scope. A failure receipt can verify correctly. Interrupted runs lack a complete evidence closure and must not be silently restarted. Cases deliberately tamper with their own disposable receipt/log state; they never target a real project journal. Verification does not reconstruct every fixture journal, certify hostile-code containment, attest a server's behavior or establish superiority over another harness.

Use a working Node 22+ runtime. Report loader/dependency failures accurately instead of modifying the system installation or claiming execution happened. The broader macOS isolation/real-provider qualification remains separate from this trusted CLI mode.
