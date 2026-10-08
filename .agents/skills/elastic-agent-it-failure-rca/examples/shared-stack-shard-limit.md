# Worked example: healthy agent, zero documents — the backing stack rejected the writes

Issue [#17043](https://github.com/elastic/elastic-agent/issues/17043), an auto-filed Analytics issue for `TestAgentMetricsInput/agent`. Analyzed 2026-10-07 on build 14251 (artifacts expire ~14 days after the build, so the commands below won't reproduce after mid-October). It shows the full path — issue → Run → build → job → artifacts → bundle → cause — for a failure that is **not an agent bug**, and the pitfalls on the way.

## Report

**Failure mode.** `TestAgentMetricsInput/agent` (and `/otel`) fail in `beat_receivers_test.go:630`: `Condition never satisfied … Expected to find at least one document for metricset cpu in index .ds-metrics-system.cpu-<ns>* … got 0` (`"0" is not greater than "0"`). `compare_documents` then fails as a knock-on. Windows (amd64 and arm64) in the issue's examples; the same test also failed on Linux retries in the same build.

**Occurrence analyzed.** The issue's single Run `f87ee8ed-…` → [elastic-agent-extended-testing #14251](https://buildkite.com/elastic/elastic-agent-extended-testing/builds/14251) (`main`, `f4069c5415be`, 9.6.0-SNAPSHOT). Job `01a10cbf-d2b6-459d-9157-88fe2553fbe7`, the **retry** of `windows:amd64:tier3:sudo:default:…windows-2025`. The first attempts of these jobs did not fail the test; the retries did.

**Evidence chain.**
- **The agent is fine.** `state.yaml`: agent `state: 2`, every component `state: 2` with `version_info.name: beat-v2-client` (process runtime). L1 and the beat behaved correctly.
- **The beat says its output was rejected.** `logs/elastic-agent-*/elastic-agent-20261005.ndjson` at 16:20:07 and 16:20:17: `Failed to index 6 events in last 10s: events were dropped!` (component `system/metrics-default`).
- **The reason is only in the events log.** `logs/elastic-agent-*/events/elastic-agent-event-log-20261005.ndjson` has 20 warn lines (`log.logger: elasticsearch`) ending in `status=400): … illegal_argument_exception … Validation Failed: 1: this action would add [2] shards, but this cluster currently has [3000]/[3000] maximum normal shards open`.
- **Not runtime-specific.** The `TestAgentMetricsInput-otel-…` bundle (otel runtime) has the same error, 19 times.
- **Why this test notices.** It uses a fresh namespace per run, so ingesting means creating new data streams (new shards), which a full cluster refuses. Tests share one ESS stack (`docs/test-framework-dev-guide.md` §"Test namespaces").
- **Breadth.** Directly proven only for the two bundles above. Other failing jobs in the build (four Windows, three Linux retries) show the same symptom in the same time window but were not opened. The build had ~55 failed or retried script jobs, i.e. heavy load on one stack.

**Suspected cause: infra** — the shared CI stack ran out of shard budget (`cluster.max_shards_per_node`). Test hygiene may contribute (per-test data streams that nothing deletes); not checked.

**Confidence.** High that Elasticsearch rejected the writes because of the shard cap (verbatim error in two independent bundles). Medium on why the stack was full.

**Next step.** On the stack, check total shard count and the largest index patterns; look at cleanup of per-test data streams and at ILM/rollover. If the stack sits near 3000 chronically, add cleanup or raise the CI stack's shard budget.

## How it was done (commands that produced the evidence)

```bash
gh issue view 17043 -R elastic/elastic-agent --json body,comments > issue.json            # Run + Time pairs: locating-the-failure.md
bk api --analytics "/suites/elastic-agent-ci/runs/<run-id>/failed_executions?per_page=100" 2>/dev/null > fe.json
jq -r '.[] | select(.test_name | endswith(" TestAgentMetricsInput/agent")) | .tags["build.url"]' fe.json | sort -u
bk api "/pipelines/elastic-agent-extended-testing/builds/14251?include_retried_jobs=true" 2>/dev/null > build.json
# ~55 failed/retried jobs: fetch every candidate log and count which ones contain the failure
for j in $(jq -r '.jobs[] | select(.type=="script" and (.state=="failed" or .retried==true)) | .id' build.json); do
  bk job log "$j" -p elastic-agent-extended-testing -b 14251 2>/dev/null \
    | perl -pe 's/\e_(bk;t=\d+\a)?//g; s/\e\[[0-9;]*[A-Za-z]//g' > "logs/$j.log"
done
grep -aHc -- '--- FAIL: TestAgentMetricsInput/agent' logs/*.log | grep -v ':0$'
P=gs://buildkite-elastic-agent/<pipeline.id>/<build.id>/<job-id>
gcloud storage cp "$P/build/*.out.json" "$P/build/diagnostics/TestAgentMetricsInput-*-diagnostics.zip" art/
# in the unzipped bundle: why was output rejected?
grep -aoE 'status=[0-9]+\): .{0,200}' logs/*/events/*.ndjson | sort | uniq -c | sort -rn | head
```

## Pitfalls this example illustrates

- **A healthy bundle plus zero documents is not an agent problem.** Check whether the agent *tried* to ship (`events were dropped`, output errors) and why it failed, before reading agent code.
- **The reason for a rejected write is in `logs/*/events/`, not the main agent log.** The agent log only says events were dropped.
- **Retries can fail when first attempts passed.** Stack state changes over a build's lifetime; don't assume the first attempt is the interesting one.
- **Don't generalize from two bundles.** The report says which jobs were proven and which were inferred.
- **Auto-filed issues list several examples but may carry one Run**; one Example can be a different failure (here, a Windows arm64 example ending in `STARTING`) — say so rather than folding it in.
