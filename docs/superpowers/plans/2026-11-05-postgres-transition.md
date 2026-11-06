# Signet Postgres transition plan

Move sessions and agent grants from JSON files on one Fly volume to Postgres. People who Allow agents and the operator who runs Signet keep the same Allow and Revoke ceremony. The rule is one durable primary for account data before a second Signet machine. PR order is PG-1, then PG-2, then PG-3, then PG-4.

## How to read this

One box is one unit of work. Every box names the evidence that checks it. A nested box is a sub-step of the box above it. Check a box only when its evidence exists, a file, a log line, a screenshot, a test run, or a SHA. The body is a how-to. The appendices explain and record.

The program runs `pstack/skills/poteto-mode/playbooks/autopilot-stack.md`. Owners build and verify each PR to merge-ready. The operator lands PG-1 through PG-4 bottom-up. This repo's trunk branch is `master`. When a checklist line shows `origin/main`, fetch `origin/master` instead.

Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

## Program checklist

### Arm the program

- [ ] State the protocol and this plan to the operator, then stop. Start execution only on the operator's explicit go.
- [ ] Read these from trunk at program start. Re-read them at every tick.
  - [ ] `git show origin/main:pstack/skills/poteto-mode/playbooks/autopilot-stack.md`
  - [ ] `git show origin/main:pstack/skills/swarm/SKILL.md`
  - [ ] `git show origin/main:pstack/skills/poteto-mode/playbooks/opening-a-pr.md`
  - [ ] `git show origin/main:pstack/skills/how/SKILL.md`
  - [ ] `git show origin/main:pstack/skills/technical-writing/SKILL.md`
  - [ ] `git show origin/master:docs/superpowers/specs/2026-11-05-agent-login-authorization.md` after agent-login merges, or the tip of `cursor/agent-login-authorization-doc-cf52` until then
- [ ] On the operator's go, arm the audit tick as `/loop 1h` with the tick prompt below. Never leave the cadence to memory.
- [ ] Use this tick prompt, verbatim. "Re-read the execution playbook from trunk. Audit the operation against it and fix drift in this tick. Probe every active lane and judge progress by side effects only. Stand down a stuck lane and dispatch its replacement now. Then post a short status message to the operator in chat only when the audit found a tracked change that no earlier status message reported, such as a PR opened, a code-ready head, a round launched or closed, a verdict, a merge, a stuck agent and the action taken, a blocker added or cleared, or a decision only the operator can make. Name every such change and nothing else. Do not repeat a table, the merged list, or an unchanged blocker. If the audit found none, end the turn with no reply text. Either way, log this tick's row in your decision trail. The row names the items reported, or none."
- [ ] On the operator's hold or stand-down, send every owner a zero-writes order at once.
- [ ] Hold until https://github.com/rodmanlau/signet/pull/2 is merged, or stack every PG branch on that PR's head. Grants and Allow must exist before store ports wrap them.

### Spawn owners

- [ ] Spawn one owner per PR with the full lifecycle the execution playbook names.
- [ ] Follow this dependency graph. Start dependent work only after its parent merges, or base it on the parent branch when the execution playbook stacks.
  - [ ] PG-1 is first. Branch from `master` after agent-login lands, or from the agent-login head.
  - [ ] PG-2 after PG-1.
  - [ ] PG-3 after PG-2.
  - [ ] PG-4 after PG-3.
- [ ] Hold the file boundaries. PG-1 touches only `packages/server/src/**` and server tests for ports. PG-2 may add `packages/server/migrations/**` and a `pg` dependency. PG-3 owns import scripts and admin cutover docs. PG-4 owns the scale runbook and any metrics endpoint.
- [ ] Hold the review gate. No PG PR in this plan changes an Allow or Revoke interaction. None are review-gated for screenshots.

### PR mechanics, for every PR

- [ ] Resolve the forge once. Default to `gh`; if `command -v origin` succeeds and Origin can resolve the repository, use `origin pr` for every PR operation. Record any fallback to `gh`. Never require `gt`.
- [ ] Open the PR ready, never draft, per **Opening a PR**. Use the run's built-in PR tool when it has one, else `origin pr create --status open --base <base-branch>` or `gh pr create --base <base-branch>` according to the resolved forge. A stack child targets its parent branch.
- [ ] Run the repo's lint and typecheck once before the PR-facing push. Push with hooks on.
- [ ] Run `/deslop` before each commit and `/no-comments` before review.
- [ ] Triage every Bugbot and security-reviewer comment per `../references/bugbot-triage.md`.
- [ ] Rebase onto current trunk before the code-ready report and babysit. Keep that merge base in fix rounds. Rebase again only at merge prep, on a `git merge-tree` conflict with trunk, on a CI failure that comes from a change on trunk, or when a known concurrent change to the same files lands.

### Verdict and merge, for every PR

- [ ] A full swarm runs once, at the code-ready head. Another full swarm runs only for new behavior, a redesign, or a large new diff. A rebase, a merge-conflict resolution, or a minor fix gets a single verifier at the new head, and a wording-only change gets none. Run each full swarm per `pstack/skills/swarm/SKILL.md`. One gates lane. The ten live lanes from the PR's **Verify, live** block. The perf lane from its **Verify, perf** block. Two or more audit lanes, each with its own focus, that read the diff and the receipts and distrust the PR body. The root audits the receipts in the merge-ready report before the verdict.
- [ ] Judge every finding by the execution playbook's blocking rule. The verdict is clean when none blocks. A failure on trunk behavior in a lane marked `Regression lane against trunk.` is recorded against trunk and does not block the PR. A new head gets a fresh verdict, except for results that stay valid under the patch-id rule in `playbooks/shipping.md`.
- [ ] Owners stop at merge-ready. The operator squash-merges bottom-up. Rebase each child onto the new trunk after its parent lands. Patch-id rules from `playbooks/shipping.md` apply.

### Boot recipe, for every live lane

Each live lane runs on its own cloud VM at the PR head. Drive HTTP with `curl` and Node scripts until `control-cli` from `cursor-team-kit` is available in the environment. Prefer `control-cli` when present.

- [ ] `git fetch origin <head-branch> && git checkout <head SHA>`.
- [ ] `npm ci` and start `@agenticage/server` with a temp sessions path (PG-1) or `DATABASE_URL` pointing at a disposable Postgres (PG-2 and later). Wait until the listen log or a TCP connect on the port succeeds.
- [ ] Deliver input only through HTTP to the documented routes. Read-only diagnostics are response status, response body, and for Postgres the row counts from `psql` or a one-shot Node query.
- [ ] Save every screenshot to `/tmp/swarm-<pr-id>/worker-<n>/<slug>.png` and return the paths with the report. For API-only lanes, save the response body text as `<slug>.txt` and a one-line status PNG or text capture named `<slug>.png` so the lane still has a named artifact.

## Extract store ports (PG-1)

**Depends on.** Agent-login grant gate on trunk or stacked head (https://github.com/rodmanlau/signet/pull/2).

**Files.**

- [ ] Edit `packages/server/src/main.ts`.
- [ ] Edit `packages/server/src/grants.ts`.
- [ ] Create `packages/server/src/stores.ts` (or split `session-store.ts` and `grant-store.ts`).
- [ ] Edit `packages/server/test/grants.test.ts`.
- [ ] Edit `packages/server/test/connect.test.ts`.
- [ ] Create `packages/server/test/stores.test.ts` if the ports need their own cases.

**Build.**

- [ ] Define `SessionStore` and `GrantStore` ports with `load`, `get` or `read`, `put` or `issue`, `delete`, and for grants `isGranted`, `upsert`, `revoke`, and `listForOwner`.
- [ ] Keep JSON file adapters as the only production backend in this PR. `Ctx` holds the ports, not raw maps for persistence.
- [ ] Preserve corrupt-session throws and corrupt-grants soft-fail behavior behind the adapters.

**You see.**

- [ ] `npm test` passes with the same HTTP behavior as before the refactor. Ungranted agent proofs still return 403. Granted proofs still return 200.

**Verify, unit.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] `packages/server/test/stores.test.ts` or updated grant and connect tests cover JSON load, write, and the soft-fail path. Run `npm test`.

**Verify, live.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked. Ten lanes on `grok-4.7-xhigh-fast` at the PR head, per the boot recipe.

- [ ] Lane 1. Regression lane against trunk. Run a granted `POST /agent-proof` and a human `GET /connect` with a test session at trunk and head. If trunk lacks grants, record that and gate the grant 403 and 200 paths plus the session cookie round trip at head. Save `regression-proof.png`. Pass when statuses match the predicates above.
- [ ] Lane 2. Missing grants file. Start with only a sessions path. Save `missing-grants.png`. Pass when `/agent-proof` is 403 and `/connect` still serves.
- [ ] Lane 3. Corrupt grants file. Write `{` into `agent-grants.json`. Save `corrupt-grants.png`. Pass when the process listens and agent proofs stay 403.
- [ ] Lane 4. Corrupt sessions file. Save `corrupt-sessions.png`. Pass when the process exits or refuses to listen with the existing error text.
- [ ] Lane 5. Issue session via `/test-login` then `/connect`. Save `session-issue.png`. Pass when `#signet-proof=` appears.
- [ ] Lane 6. Logout clears the session and the next `/connect` shows providers. Save `session-logout.png`. Pass when the providers page returns.
- [ ] Lane 7. Ticket then Allow then proof. Save `allow-flow.png`. Pass when the second proof is 200.
- [ ] Lane 8. Revoke then proof. Save `revoke-flow.png`. Pass when proof is 403 again.
- [ ] Lane 9. Restart the process with the same files. Save `restart-persist.png`. Pass when the session cookie and the grant still work.
- [ ] Lane 10. Concurrent Allow and session write under load of 20 mixed requests. Save `concurrent-writes.png`. Pass when no 500 and both files remain valid JSON.

**Verify, perf.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Metric. Wall time for 50 sequential granted `POST /agent-proof` calls at trunk and at head. Also record p50 for one call as the diff-added work stays a refactor.
- [ ] Probe. A Node script that signs once then posts 50 times, run interleaved trunk then head then trunk then head.
- [ ] Baseline. Record the trunk total milliseconds first.
- [ ] Rule. Head total must stay within 1.25× trunk. Absolute budget for one call at head is under 50ms on the lane VM excluding cold start.

**Review gate.** None. PG-1 is not review-gated.

**Merge.**

- [ ] Root's clean verdict at the exact head SHA.
- [ ] Bugbot triage done.
- [ ] Rebased onto current trunk after the verdict, patch-id unchanged.
- [ ] The operator squash-merges PG-1 after merge-ready.

## Add Postgres backends (PG-2)

**Depends on.** PG-1.

**Files.**

- [ ] Edit `packages/server/package.json` to add `pg`.
- [ ] Create `packages/server/migrations/001_sessions_and_grants.sql`.
- [ ] Create `packages/server/src/pg-store.ts` (or equivalent).
- [ ] Edit `packages/server/src/main.ts` and `loginFromEnv` to read `DATABASE_URL`.
- [ ] Edit `docs/admin.md` for the new variable.
- [ ] Create server tests that skip when `DATABASE_URL` is unset and run in CI with a service container.

**Build.**

- [ ] Schema tables `sessions` (id primary key, provider, subject, label) and `agent_grants` (public_key primary key as bytea or unique base64url text, owner_provider, owner_subject, label, created_at).
- [ ] Index `(owner_provider, owner_subject)` on grants.
- [ ] When `DATABASE_URL` is set, use Postgres ports. When unset, keep JSON ports.
- [ ] Pool settings follow Fly's `pg` sample (max 10, idle timeout 300s, max lifetime 600s) as documented for Managed Postgres.

**You see.**

- [ ] With `DATABASE_URL`, Allow writes a grant row and `/agent-proof` returns 200. With no URL, JSON behavior is unchanged.

**Verify, unit.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Postgres-backed grant and session tests in `packages/server/test/`. Run `npm test` with CI Postgres service.

**Verify, live.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked. Ten lanes on `grok-4.7-xhigh-fast` at the PR head, per the boot recipe.

- [ ] Lane 1. Regression lane against trunk. JSON mode at head vs trunk granted proof. Save `pg-regression-json.png`. Pass when both return 200 for a granted key.
- [ ] Lane 2. Fresh Postgres schema apply. Save `pg-migrate.png`. Pass when both tables exist.
- [ ] Lane 3. Session issue and read through Postgres. Save `pg-session.png`. Pass when `/connect` returns a proof.
- [ ] Lane 4. Grant upsert and `isGranted`. Save `pg-grant.png`. Pass when proof is 200.
- [ ] Lane 5. Second owner cannot steal a key. Save `pg-steal.png`. Pass when Allow returns the existing conflict status.
- [ ] Lane 6. Revoke removes the row. Save `pg-revoke.png`. Pass when proof is 403.
- [ ] Lane 7. Process restart keeps rows. Save `pg-restart.png`. Pass when session and grant still work.
- [ ] Lane 8. JSON mode still works with `DATABASE_URL` unset. Save `pg-json-fallback.png`. Pass when Allow persists to `agent-grants.json`.
- [ ] Lane 9. Bad `DATABASE_URL` fails startup with a clear stderr line. Save `pg-bad-url.png`. Pass when the process exits non-zero before listen.
- [ ] Lane 10. Pool recovers after a brief Postgres restart. Save `pg-pool-recover.png`. Pass when the next proof succeeds within 30s.

**Verify, perf.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Metric. Wall time for 50 sequential granted `POST /agent-proof` calls on JSON (trunk) and on Postgres (head). Also absolute p50 for one Postgres-backed proof.
- [ ] Probe. Same interleaved Node script against both backends.
- [ ] Baseline. Record trunk JSON total milliseconds first.
- [ ] Rule. Postgres head total may exceed JSON. Absolute budget for one Postgres-backed proof is under 100ms on the lane VM excluding cold start. Fail if p50 exceeds 100ms after warmup.

**Review gate.** None. PG-2 is not review-gated.

**Merge.**

- [ ] Root's clean verdict at the exact head SHA.
- [ ] Bugbot triage done.
- [ ] Rebased onto current trunk after the verdict, patch-id unchanged.
- [ ] The operator squash-merges PG-2 after merge-ready.

## Cut over production (PG-3)

**Depends on.** PG-2.

**Files.**

- [ ] Create `scripts/import-json-to-postgres.mjs`.
- [ ] Edit `docs/admin.md` with the cutover how-to.
- [ ] Edit `fly.toml` only if a non-secret flag is required. Prefer secrets for `DATABASE_URL`.
- [ ] Create `docs/superpowers/plans/postgres-cutover-checklist.md` if the admin guide would grow too long.

**Build.**

- [ ] Import script reads `sessions.json` and `agent-grants.json` and upserts into Postgres. Idempotent on re-run.
- [ ] Cutover steps. Create Fly Managed Postgres in `iad`, attach to `signet`, set `DATABASE_URL`, stop accepting traffic or take a short window, run import against volume files, restart Signet with `DATABASE_URL`, confirm Allow and session, keep the volume until one clean week.
- [ ] Do not delete the volume in this PR.

**You see.**

- [ ] On a staging app, after import, row counts match the JSON files and a real Allow round trip works with no JSON writes.

**Verify, unit.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Import script test with fixture JSON into a disposable database. Run `npm test` and the script's own check command.

**Verify, live.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked. Ten lanes on `grok-4.7-xhigh-fast` at the PR head, per the boot recipe.

- [ ] Lane 1. Regression lane against trunk. Pre-cutover JSON Allow still documented. Save `cutover-regression.png`. Pass when the guide still describes JSON fallback for local dev.
- [ ] Lane 2. Import empty files. Save `import-empty.png`. Pass when tables stay empty and exit code is 0.
- [ ] Lane 3. Import fixture with two sessions and two grants. Save `import-fixture.png`. Pass when counts match.
- [ ] Lane 4. Re-run import. Save `import-idempotent.png`. Pass when counts stay equal and no duplicate key error.
- [ ] Lane 5. Staging attach dry-run notes. Save `mpg-attach.png`. Pass when the checklist names `fly mpg create` and `fly mpg attach`.
- [ ] Lane 6. Post-import proof on imported grant. Save `import-proof.png`. Pass when status is 200.
- [ ] Lane 7. Post-import session cookie. Save `import-session.png`. Pass when `/connect` returns a proof.
- [ ] Lane 8. New Allow after cutover writes only Postgres (JSON mtime unchanged). Save `pg-only-write.png`. Pass when the grants file mtime is unchanged and a new row exists.
- [ ] Lane 9. Rollback drill. Unset `DATABASE_URL`, restart, confirm JSON still loads the pre-cutover copy. Save `rollback.png`. Pass when proof works from JSON.
- [ ] Lane 10. Documented one-week volume retain. Save `retain-volume.png`. Pass when the admin guide states the retain window.

**Verify, perf.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Metric. Import wall time for a fixture of 1000 sessions and 1000 grants.
- [ ] Probe. Run the import script three times on a warm database and take the median.
- [ ] Baseline. No trunk import exists. Record the first median as the baseline absolute.
- [ ] Rule. Median import under 30s on the lane VM for that fixture size. Fail above 30s.

**Review gate.** None. PG-3 is not review-gated.

**Merge.**

- [ ] Root's clean verdict at the exact head SHA.
- [ ] Bugbot triage done.
- [ ] Rebased onto current trunk after the verdict, patch-id unchanged.
- [ ] The operator squash-merges PG-3 after merge-ready, then runs the live cutover on Fly in a maintenance window.

## Publish scale triggers (PG-4)

**Depends on.** PG-3.

**Files.**

- [ ] Create `docs/admin-scale.md` (or a section in `docs/admin.md`).
- [ ] Edit `packages/server/src/main.ts` only if a tiny `GET /metrics` or stderr periodic counter is required. Prefer log-based counters first.
- [ ] Create a short test or script that parses the documented trigger thresholds for typos.

**Build.**

- [ ] Write the expand-availability triggers from Appendix E into operator docs with the action for each trigger.
- [ ] Add the minimum telemetry needed to see those triggers (request counts, error rate, process count, pool wait). Do not build Redis in this PR.

**You see.**

- [ ] An operator can open the scale doc and match a live symptom to one named action.

**Verify, unit.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Doc link from `docs/admin.md` resolves. Any metrics parser test passes under `npm test`.

**Verify, live.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked. Ten lanes on `grok-4.7-xhigh-fast` at the PR head, per the boot recipe.

- [ ] Lane 1. Regression lane against trunk. Allow and proof still work after metrics hooks. Save `scale-regression.png`. Pass when proof is 200.
- [ ] Lane 2. Scale doc lists trigger T1. Save `trigger-t1.png`. Pass when the machine-count action is present.
- [ ] Lane 3. Scale doc lists trigger T2. Save `trigger-t2.png`. Pass when the pool action is present.
- [ ] Lane 4. Scale doc lists trigger T3. Save `trigger-t3.png`. Pass when the latency action is present.
- [ ] Lane 5. Scale doc lists trigger T4. Save `trigger-t4.png`. Pass when the ticket or Redis action is present.
- [ ] Lane 6. Scale doc lists trigger T5. Save `trigger-t5.png`. Pass when the cache action is present.
- [ ] Lane 7. Metrics or logs expose proof count. Save `metric-proofs.png`. Pass when a counter increases after 10 proofs.
- [ ] Lane 8. Metrics or logs expose 403 count. Save `metric-403.png`. Pass when a counter increases after an ungated proof.
- [ ] Lane 9. Admin guide links to the scale doc. Save `admin-link.png`. Pass when the link returns 200 from the repo path.
- [ ] Lane 10. False trigger check. Under 1 proof/s the doc says stay on one machine. Save `false-trigger.png`. Pass when the stay guidance is explicit.

**Verify, perf.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Metric. Overhead of metrics hooks on 50 granted proofs vs PG-3 head without hooks.
- [ ] Probe. Same 50-proof script interleaved.
- [ ] Baseline. Record PG-3-equivalent head without metrics first if measurable on the same branch toggle, else use PG-2 Postgres budget.
- [ ] Rule. Added overhead under 5ms p50 per proof. Fail if p50 rises by more than 5ms.

**Review gate.** None. PG-4 is not review-gated.

**Merge.**

- [ ] Root's clean verdict at the exact head SHA.
- [ ] Bugbot triage done.
- [ ] Rebased onto current trunk after the verdict, patch-id unchanged.
- [ ] The operator squash-merges PG-4 after merge-ready.

## Close the program

- [ ] Every box above is checked with its evidence.
- [ ] Reply to the operator with the report the execution playbook names.

## Appendix A. Prototype evidence

No prototype branch was cut for this plan. Low traffic and a single Fly machine make a maintenance-window import the obvious cutover. That choice is unproven in production until PG-3's staging lanes run.

Unproven until execution

- Fly Managed Postgres region availability for `iad` at attach time.
- Exact `pg` ESM import shape on Node 22 in this image.
- Real import duration on production-sized JSON files.

## Appendix B. Alternatives rejected

- SQLite first. Same single-writer limit as the volume. Two migrations. Rejected in the agent-login storage roadmap.
- Redis as primary for grants or sessions. Account data must survive flushes. Redis stays optional for tickets and later caches.
- Dual-write JSON and Postgres for weeks. Extra code and split-brain risk. Early Signet can take a short window instead.
- Heavy ORM (Prisma) for two tables. `pg` plus SQL matches Fly's sample and this codebase's size.
- Unmanaged `fly postgres`. Current Fly docs point operators to Managed Postgres.

## Appendix C. Risks

- Agent-login not yet on `master`. PG-1 must wait or stack. Watch PR 2.
- Cutover mistakes leave empty grants and mass 403. PG-3 rollback drill is mandatory.
- `cursor-team-kit` control skills may be absent on lane VMs. Lanes use `curl` and file artifacts. Watch boot recipe drift.
- Pool exhaustion after scaling Signet machines without raising Postgres plan limits. Trigger T2 in Appendix E.
- Leaving the volume forever hides whether Postgres is authoritative. PG-3 retain window then a later delete change outside this program.

## Appendix D. Links and reading list

- `docs/superpowers/specs/2026-11-05-agent-login-authorization.md` (storage roadmap)
- `docs/admin.md`, `fly.toml`, `Dockerfile`
- `packages/server/src/main.ts`, `packages/server/src/grants.ts`
- Fly Managed Postgres create and connect docs
- PG-1 and PG-2 owners run `how` on store ports before editing
- Contested pool or schema choices run `interrogate`
- Decision trail per `show-me-your-work` during autopilot-stack

## Appendix E. Expand-availability triggers

Stay on one Signet machine and one Managed Postgres Basic cluster while all of the following hold.

- Proof traffic stays under about 10 requests per second sustained.
- Postgres CPU stays under 50% and the `pg` pool is not waiting.
- p50 `POST /agent-proof` stays under 100ms after warmup.
- Ticket loss on deploy is acceptable (people re-open Allow).
- A single region (`iad`) meets the product need.

Expand when any trigger fires. Each trigger names the action.

| Id | Trigger (measure weekly or on alert) | Action |
| --- | --- | --- |
| T1 | Need Signet process count greater than 1 (HA, or rolling deploys without downtime on a sticky volume) | Run two or more Signet machines only after PG-3. Put Allow tickets in Redis (new program). Remove reliance on the JSON volume. |
| T2 | `pg` pool wait or Postgres connection errors under load, or connections near the plan cap (Basic lists 200 client connections) | Raise pool carefully, then upgrade the Managed Postgres plan. Do not multiply Signet machines first. |
| T3 | p50 `POST /agent-proof` over 100ms or p99 over 300ms for 15 minutes while CPU is the limiter | Explain the number with `explain-the-number`. Index or query fix first. Scale vertical Postgres next. |
| T4 | Users complain that deploys drop in-flight Allow tickets more than rarely | Move tickets to Redis with TTL 600s. Keep grants in Postgres. |
| T5 | `isGranted` QPS high enough that Postgres CPU is dominated by grant lookups while p50 still fails T3 budgets | Add a Redis or in-process cache in front of grants with invalidate on upsert and revoke. Postgres remains source of truth. |
| T6 | Multi-region latency or residency requirements appear | New program. Not a silent expansion of this one. |

Default while traffic is low. Do not pre-build T1 through T5. PG-4 only publishes the triggers and the minimum telemetry to see them.
