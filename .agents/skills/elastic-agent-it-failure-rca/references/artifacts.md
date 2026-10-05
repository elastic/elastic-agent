# Artifacts: what a job uploads, fetching, validating, reading

## What an integration-test job uploads

| Path | Contents |
|---|---|
| `build/<group>[_sudo]_<uname -spr>.integration.xml` | JUnit XML for the job's test group, e.g. `rpm_sudo_Linux_4.18.0-553.159.1.el8_10.x86_64_x86_64.integration.xml` (VM tests; built in `.buildkite/scripts/buildkite-integration-tests.sh`) |
| `build/<same>.integration.out.json` | gotestsum NDJSON — every test event with timestamps |
| `build/TEST-go-k8s-<…>.k8s.xml` / `.k8s.out.json` / `.k8s.out` | the same for Kubernetes tests (`pkg/testing/kubernetes/runner.go`) |
| `build/TEST-report.html` | HTML rendering of the JUnit; skip it |
| `build/k8s-logs-*/**` | pod logs, on Kubernetes jobs |
| `build/diagnostics/<Test-Name>-<RFC3339 with : → ->-diagnostics.zip` | agent diagnostics bundle, one per fixture that collected diagnostics (`pkg/testing/fixture_install.go`); subtest `/` → `-` |
| `build/diagnostics/<…>-ProcessDump-<phase>.json` | process listing captured around install/cleanup |
| `build/distributions/**` | packages, on packaging jobs — ignore |

A job that failed before the agent was installed typically has only the JUnit, the gotestsum JSON and the HTML report.

## Fetching

Always from GCS — see [access.md](access.md) §"GCS" for why Buildkite downloads don't work and how the path is built.

```bash
P="gs://buildkite-elastic-agent/<pipeline.id>/<build.id>/<job-id>"
gcloud storage ls -l "$P/**"
mkdir -p "$RCA_DIR/build"
gcloud storage cp "$P/build/*.xml" "$P/build/*.json" "$RCA_DIR/build/"
gcloud storage cp -r "$P/build/diagnostics" "$RCA_DIR/build/"      # only if the listing shows it
gcloud storage cat "$P/build/<file>.integration.xml" | grep -c '<failure'   # peek without downloading
```

**Retention is ~14 days.** After that the GCS objects are gone while the Buildkite API still lists them with a `download_url`. To tell "expired" from "never uploaded", compare the job's artifact metadata with GCS: listed by `bk api /pipelines/<slug>/builds/<n>/jobs/<job-id>/artifacts` but "matched no objects" in GCS → expired; not listed → never uploaded.

## Validating

Required whenever a file came from anywhere other than `gcloud storage` (which verifies checksums itself), and cheap enough to do anyway:

```bash
file "$RCA_DIR"/build/* "$RCA_DIR"/build/diagnostics/*          # HTML document → it's a login page, not the artifact
for z in "$RCA_DIR"/build/diagnostics/*.zip; do unzip -tq "$z"; done
```

Compare sizes with `gcloud storage ls -l` or the Buildkite artifact metadata's `file_size`. A ~900 KB "XML" that `file` calls HTML is the Google sign-in page.

## Reading test output

### JUnit — the failing assertions

`<testcase>` elements have `name` (full test name with subtests), `classname` (Go package) and `time` (seconds). There is **no per-testcase timestamp** — only `<testsuite timestamp>` (suite start). The failure text is in `<failure>`'s body.

```bash
python3 - "$RCA_DIR"/build/*.xml <<'EOF'
import sys, xml.etree.ElementTree as ET
for path in sys.argv[1:]:
    root = ET.parse(path).getroot()          # raises on HTML/garbage instead of reporting "no failures"
    for tc in root.iter('testcase'):
        f = tc.find('failure')
        if f is None:
            continue
        print(f"\n=== {tc.get('name')}  ({tc.get('time')}s)  [{path.rsplit('/', 1)[-1]}]")
        text = (f.text or f.get('message') or '').strip()
        print(text if len(text) < 6000 else text[:3000] + '\n  [...]\n' + text[-3000:])
EOF
```

A parent test fails whenever a subtest fails; read the deepest failing subtest first. The `Error Trace:` / `Error:` block is the assertion; the lines before it are the test's own `t.Log` output.

### gotestsum JSON — the full, timestamped test log

```bash
TEST='TestFoo/sub'
jq -j --arg t "$TEST" 'select(.Action=="output" and (.Test==$t or ((.Test // "") | startswith($t + "/"))))
  | "\(.Time[11:23]) \(.Output)"' "$RCA_DIR"/build/*.out.json > test.log
grep -v -e '>> running binary with: \[.* status' -e 'agent status: {' test.log > test.filtered.log   # drop polling noise
```

- Polling tests repeat the same `t.Log` line hundreds of times (often with a full status dump). Collapse consecutive lines by call site to get the test's story in a dozen lines:
  ```bash
  awk 'match($0, /[A-Za-z0-9_]+\.go:[0-9]+:/) { k = substr($0, RSTART, RLENGTH)
      if (k != last) { if (last != "") printf "%s .. %s  x%-4d %s\n", first, prev, n, sample; last = k; n = 0; first = $1; sample = substr($0, RSTART, 160) }
      n++; prev = $1 }
    END { if (last != "") printf "%s .. %s  x%-4d %s\n", first, prev, n, sample }' test.log
  ```
- The failure time is the `Time` of the `{"Action":"fail","Test":"<name>"}` event: `jq -r --arg t "$TEST" 'select(.Action=="fail" and .Test==$t) | .Time' …`. Use it to pick the right diagnostics bundle and to bound the log window in the bundle.
- Which other tests failed in the same job (and when): `jq -r 'select(.Action=="fail" and .Test) | "\(.Time) \(.Test)"' …`. Several unrelated tests failing within the same minute points at the environment.
- Tests in a job run one after another on the same VM, in shuffled order (`-test.shuffle on`), so the tests that ran just before the failure tell you what state the VM was in.

### Job log — everything outside the test binary

```bash
bk job log <job-id> -p <slug> -b <n> 2>/dev/null > job.raw.log
perl -pe 's/\e_(bk;t=\d+\a)?//g; s/\e\[[0-9;]*[A-Za-z]//g' job.raw.log > job.log      # strip timestamp markers and colour codes
grep -a -n -E -e '(---|===) FAIL:' -e 'DONE [0-9]+ tests' -e '^(~~~|---|\+\+\+) ' job.log | head -50   # failures, totals, section headers
```

Raw lines start with an `ESC _bk;t=<epoch-ms> BEL` timestamp marker and contain ANSI colour codes; the `perl` line removes both. Keep `job.raw.log` when you need the times (`grep -a` it for the epoch-ms). `bk job log --no-timestamps` leaves a stray `ESC _` on every line, so don't rely on it. gotestsum's summary uses `=== FAIL: <pkg> <Test> (…)`, and `DONE N tests, M skipped, K failures` gives the job's totals. The job log contains VM image and agent version, setup steps from `.buildkite/scripts/` (e.g. the "disable background package managers" step), and gotestsum's `standard-quiet` output, which prints the full output of every failed test — so it is a usable fallback when GCS is unavailable.
