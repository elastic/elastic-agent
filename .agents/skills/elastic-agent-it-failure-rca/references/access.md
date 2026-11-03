# Access: GitHub, Buildkite, GCS

The RCA needs three kinds of read access. Each can be satisfied several ways; use whichever the environment already has, probe it with the real operation, and report all gaps to the user in one message.

## Inventory (cheap, no side effects)

```bash
for t in gh bk gcloud curl jq; do printf '%-7s ' "$t"; command -v "$t" || echo MISSING; done
printf 'GH_TOKEN:%s GITHUB_TOKEN:%s BUILDKITE_API_TOKEN:%s\n' \
  "${GH_TOKEN:+set}" "${GITHUB_TOKEN:+set}" "${BUILDKITE_API_TOKEN:+set}"
gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | grep . || echo 'gcloud: no active account'
```

Also check your own tool list for MCP tools whose names contain `github` or `buildkite`. A server reported as "failed to connect" is unavailable for this session — mention it to the user, then use another provider.

Never print token values. Checking whether a variable is set is fine.

**Probe order:** GitHub first — reading the issue gives you the Run/build IDs that the Buildkite probe needs. Then Buildkite (the build or Run), then GCS. Don't stop at the first failure; run every probe you can.

## GitHub (issue body + comments)

| Provider | Probe / use |
|---|---|
| GitHub MCP tools | read the issue with the issue-read tool |
| `gh` | `gh issue view <N> -R elastic/elastic-agent --json title,body,comments` |
| unauthenticated `curl` (public repo, 60 req/h) | `curl -sf https://api.github.com/repos/elastic/elastic-agent/issues/<N>` and `…/<N>/comments` |

Known failure modes:
- **GitHub plugin MCP: "Authorization header is badly formatted".** The plugin's config sends `Bearer ${GITHUB_PERSONAL_ACCESS_TOKEN}` and that variable is unset. Use `gh` meanwhile; if the user wants the MCP, they need `GITHUB_PERSONAL_ACCESS_TOKEN` in the environment Claude Code starts from (e.g. from `gh auth token`).
- **`gh auth status` can report a failing stale account while `GH_TOKEN` works.** Don't use it as the probe; fetch the issue.

Remediation to suggest: `! gh auth login -h github.com`.

## Buildkite API (Test Engine, builds, jobs, job logs, artifact metadata)

Needed token scopes: `read_builds`, `read_build_logs`, `read_artifacts`, `read_suites` (Test Engine). `read_pipelines` is useful.

| Provider | Base / usage |
|---|---|
| Buildkite MCP tools | builds, jobs, logs, Test Engine where exposed. For artifact **contents** still use GCS (below). |
| `bk` CLI | `bk api /pipelines/<slug>/builds/<n>`, `bk api --analytics /suites/elastic-agent-ci/runs/<id>/failed_executions`, `bk job log <job-id> -p <slug> -b <n>` |
| `curl` + `BUILDKITE_API_TOKEN` | `curl -sf -H "Authorization: Bearer $BUILDKITE_API_TOKEN" https://api.buildkite.com/v2/organizations/elastic/<path>`; Test Engine under `https://api.buildkite.com/v2/analytics/organizations/elastic/suites/elastic-agent-ci/` |

Probe: fetch the build you need (`/pipelines/elastic-agent/builds/<n>`), and for an analytics-filed issue, the Run. With curl you can also read the token's scopes: `curl -sf -H "Authorization: Bearer $BUILDKITE_API_TOKEN" https://api.buildkite.com/v2/access-token | jq .scopes`.

Known failure modes:
- **`bk api` prepends `/organizations/<org>` to every path.** Pass `/pipelines/elastic-agent/…`. A full `/organizations/elastic/…` path 404s as `…/organizations/elastic/organizations/elastic/…`, which looks like an auth failure but isn't. Non-org endpoints such as `/access-token` are unreachable via `bk api`.
- **`bk` picks up `BUILDKITE_API_TOKEN` from the environment** and prints `Warning: using BUILDKITE_API_TOKEN environment variable` on stderr. Harmless; keep stderr out of anything you pipe to `jq`.
- **Pagination.** List endpoints return 30 items by default. Pass `per_page=100` and follow `page=` (or the `Link` header). Builds can have 300+ jobs (inline in the build JSON) and 1000+ artifacts.
- **Save API responses to files, or use `printf '%s'`, not `echo "$json"`.** zsh's `echo` interprets backslash escapes inside commit messages and corrupts the JSON (`jq: parse error: Invalid string: control characters…`).
- **Retried jobs are hidden by default.** Add `include_retried_jobs=true` to build requests — for flaky tests, the failed first attempt is exactly the retried job.

Remediation to suggest: `! bk auth login`, or a token from https://buildkite.com/user/api-access-tokens with the scopes above, exported as `BUILDKITE_API_TOKEN` in the environment Claude Code is started from (an `export` via `!` does not persist to later commands).

## GCS (artifact contents)

**Why this is needed.** The `elastic` org stores Buildkite artifacts in its own bucket. An artifact's `download_url` returns `302 → https://storage.cloud.google.com/buildkite-elastic-agent/…`, a browser endpoint that needs a Google login cookie. Non-browser clients receive a Google sign-in page with HTTP 200, so `curl -L`, `bk artifacts download`, and any tool that follows the redirect save HTML under the artifact's file name and report success. `gcloud storage` is the only non-browser path that works.

**Path layout** (same bucket for `elastic-agent` and `elastic-agent-extended-testing`):

```
gs://buildkite-elastic-agent/<pipeline.id>/<build.id>/<job.id>/<artifact path>
```

`pipeline.id` and `build.id` are the UUIDs `.pipeline.id` and `.id` in the build JSON; `job.id` is `.jobs[].id`. For another pipeline, derive the prefix from one redirect instead of assuming the bucket:

```bash
curl -s -o /dev/null -D - -H "Authorization: Bearer $BUILDKITE_API_TOKEN" "<download_url>" | grep -i '^location'
# replace https://storage.cloud.google.com/ with gs:// and drop the query string
```

**Auth.** Plain user credentials from `gcloud auth login` are enough. Application-default credentials (ADC) are **not** needed — don't ask the user to set them up.

**Probe.** Before the job is known (e.g. in the preflight, or when the Buildkite API is unavailable): `gcloud storage ls gs://buildkite-elastic-agent/ | head -1` — proves an account and bucket-level access, but not object read. Once the job is known: `gcloud storage ls -l "gs://buildkite-elastic-agent/<pipeline.id>/<build.id>/<job.id>/**"`.
- *"One or more URLs matched no objects"* — the objects expired (retention is ~14 days, while the Buildkite API keeps listing them) or the job never uploaded any. The artifact metadata and job log tell you which.
- *401 / 403 / "does not have storage.objects.list access"* — the active account lacks read access to the bucket. Tell the user which account is active and that it needs read access to `gs://buildkite-elastic-agent`.

**Performance.** Always include the job id in the path. Wildcards across jobs (`<build.id>/*/build/…`) scan the whole build and take tens of seconds or more per build.

Remediation to suggest: install `google-cloud-cli`, then `! gcloud auth login`.

## Degraded modes

| Missing | Still possible | Offer the user |
|---|---|---|
| GCS | Issue text; job log. The job log contains gotestsum's output for failed tests, including assertion messages, and all setup steps — often enough for infra and pre-install failures. No bundle, no timestamps per `t.Log` line. | `! gcloud auth login`, or downloading the job's artifacts in a browser (see below) |
| Buildkite API | Issue text, test source, git history. A *lead* on the build from GitHub commit statuses (below) — label anything found this way unconfirmed. With a local artifacts dir, steps 4–7 work. | `! bk auth login` / a token, or the job log + artifacts from the browser |
| Buildkite API **and** GCS | GitHub and local source only. You can't see the failure itself — say so rather than guessing the cause. | fix access, or the job log + artifacts from the browser |
| GitHub | Everything, if the user gives a build/job URL or pastes the issue text | paste the issue, or `! gh auth login -h github.com` |

GitHub commit statuses for a suspected commit carry Buildkite build and job URLs, states and contexts:

```bash
gh api repos/elastic/elastic-agent/commits/<sha>/statuses \
  --jq '.[] | select(.target_url | test("buildkite")) | "\(.state) \(.context) \(.target_url)"'
```

Test Engine carries no failure text (`failure_reason` is just "Got 1 failure and 0 errors."; `failure_expanded` is null), so it can't replace the job log or JUnit.

**Browser fallback.** Unauthenticated requests to buildkite.com (build pages, `.json`, logs) return a login page, so the only no-credentials path for CI data is the user's browser. Give them the click path from what you have: a human-filed issue's job URL → the job's log download and Artifacts tab; for an Analytics issue, the **Buildkite Link** (Test Engine test page) → failed execution → build → the failing job → log and Artifacts. Ask for the log and `build/*.xml`, `build/*.out.json`, `build/diagnostics/*` in one local directory.

## Reporting gaps

Send one message, after the inventory and probes:

```
To run this RCA I still need:
1. <capability> — <probe result, quoted briefly> → <fix, e.g. `! gcloud auth login`>
2. …
Artifacts for this failure expire around <occurrence date + ~14 days>.
Without these I can still <what's possible, and what I've already learned>.
Alternatively <browser fallback, if relevant>. Proceed with that, or fix access first?
```

Mention broken-but-irrelevant providers (e.g. a GitHub MCP that failed while `gh` works) only as an FYI.
