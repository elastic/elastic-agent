# Buildkite Artifacts

## Artifact layout

Integration test jobs upload their artifacts under the `build/` prefix. The files you need:

| Path pattern | Contents |
|---|---|
| `build/*.integration.xml` | JUnit XML — one file per test suite (e.g. `build/TEST-TestNetworkTraffic.integration.xml`) |
| `build/*.integration.out.json` | gotestsum NDJSON — raw Go test output with timestamps; one file per suite |
| `build/diagnostics/*.zip` | Elastic-agent diagnostics bundles — one per agent per test run |
| `build/TEST-report.html` | HTML summary of all test results (useful for quick triage across suites) |

## Downloading artifacts

### Preferred: REST API (requires `BUILDKITE_API_TOKEN`)

```bash
<ITRCA> download <org/pipeline> <build> <jid>
```

The token needs the `read_artifacts` scope. Get one at https://buildkite.com/user/api-access-tokens.

The command filters to the four artifact types above and writes them to:
```
$TMPDIR/it-rca/<build>-<jid>/build/...
```
The destination path is printed on the last line.

### Fallback: bk CLI

The `bk` CLI download path requires the GraphQL scope on its token, which most read-only tokens don't have. Use the REST API path above when possible.

### Direct GCS access

Buildkite artifacts are stored in Google Cloud Storage. If you have a `gs://` path (e.g. from a Buildkite artifact URL or a colleague), you can fetch directly with the `gcloud` CLI — `curl`/`wget` won't work against these buckets.

**Preflight check before any GCS download:**

```bash
# 1. gcloud present?
command -v gcloud || echo "ERROR: gcloud not found — install google-cloud-cli"

# 2. authenticated?
gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>&1

# 3. application-default credentials (needed for storage)?
gcloud auth application-default print-access-token &>/dev/null \
  && echo "ADC OK" \
  || echo "WARNING: no ADC — run: gcloud auth application-default login"
```

If step 1 fails: tell the user to install `google-cloud-cli` and re-run.  
If step 2 shows no active account: tell the user to run `gcloud auth login`.  
If step 3 warns: tell the user to run `gcloud auth application-default login`.

Once all three pass:

```bash
# gcloud storage (modern, faster)
gcloud storage cp "gs://<bucket>/<path>/build/diagnostics/*.zip" /tmp/

# gsutil (legacy fallback, same credentials)
gsutil cp "gs://<bucket>/<path>/build/diagnostics/*.zip" /tmp/
```

### Setting `$RCA_DIR`

Capture the output of `<ITRCA> download` and assign it:
```bash
RCA_DIR=$(<ITRCA> download elastic/elastic-agent-extended-testing 1234 019741ab-...)
```
Progress messages go to stderr; the destination path is the only thing on stdout, so a plain subshell capture is sufficient and correct. Do not add `2>&1 | tail -1` — it is redundant and fragile.

All subsequent commands that take `<rca-dir>` use this variable.

## Identifying the pipeline slug

The pipeline slug is embedded in the Buildkite build URL:

```
https://buildkite.com/<org>/<pipeline>/builds/<build>
                       ^^^^  ^^^^^^^^
```

| Context | Typical slug |
|---|---|
| PR-triggered run | `elastic/elastic-agent` |
| Scheduled IT matrix | `elastic/elastic-agent-extended-testing` |
| Specific team pipeline | `elastic/elastic-agent-<team>` |

When the URL comes from a GitHub issue, `<ITRCA> issue` extracts the slug automatically.

## Identifying the job ID (jid)

The jid is the UUID in the `?jid=` query parameter of the Buildkite job URL:

```
https://buildkite.com/elastic/elastic-agent/builds/38654/table?jid=019741ab-1234-5678-abcd-000000000000
                                                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
```

If the URL has no `?jid=`, use:
```bash
<ITRCA> parse-build-url <url>
```
This queries the Buildkite API and lists all script-type jobs in the build as `jid: <uuid>  name: <job-name>` lines. Scan the output for the job whose name matches the failing test suite, then use that jid.

## What to do when artifacts are missing

If `<ITRCA> download` returns no matching artifacts:

1. Confirm the build number is correct — issues sometimes paste the pipeline overview URL rather than a specific build.
2. Check if the build is old enough for artifacts to have expired (Buildkite default retention is 6 months).
3. Verify the pipeline slug — a wrong slug returns an empty artifact list, not an error.
4. Ask the user to re-run the failing test with `TEST_INTEG_CLEAN_ON_EXIT=false` to preserve diagnostics locally.

**Never invent artifact paths or synthesize content from memory** — always tell the user when artifacts are unavailable and ask them to verify the URL.
