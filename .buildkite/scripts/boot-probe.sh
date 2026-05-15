#!/usr/bin/env bash
#
# Boot-time noise probe.
#
# Started in the background from pre-command on freshly-booted CI VMs, captures
# what the machine is doing during the first ~10 minutes after boot, then exits.
# Output lives under /tmp/boot-probe and is uploaded by pre-exit.
#
# Self-gates: only runs when systemd is PID 1 (i.e. a real VM, not a container)
# and when the system was booted recently.

set -uo pipefail

OUT=/tmp/boot-probe
SAMPLE_INTERVAL=5
SAMPLE_DURATION=600       # 10 minutes
MAX_UPTIME_SECS=1800      # skip if VM is older than 30 min (persistent agent)

# --- gates -------------------------------------------------------------------
if [[ ! -r /proc/1/comm ]] || [[ "$(cat /proc/1/comm)" != "systemd" ]]; then
    exit 0
fi

uptime_secs=$(cut -d. -f1 /proc/uptime)
if (( uptime_secs > MAX_UPTIME_SECS )); then
    exit 0
fi

mkdir -p "$OUT"
exec >"$OUT/probe.log" 2>&1

# --- one-shot snapshot at job start -----------------------------------------
{
    echo "started_at=$(date -u +%FT%TZ)"
    echo "uptime_at_start_s=${uptime_secs}"
    echo "kernel=$(uname -r)"
    echo "buildkite_pipeline=${BUILDKITE_PIPELINE_SLUG:-}"
    echo "buildkite_step=${BUILDKITE_STEP_KEY:-}"
    echo "buildkite_agent=${BUILDKITE_AGENT_NAME:-}"
    echo "buildkite_job=${BUILDKITE_JOB_ID:-}"
    [[ -r /etc/os-release ]] && cat /etc/os-release
} > "$OUT/snapshot.txt"

systemd-analyze                                     > "$OUT/systemd-analyze.txt"    2>&1 || true
systemd-analyze blame                               > "$OUT/systemd-blame.txt"      2>&1 || true
systemd-analyze critical-chain                      > "$OUT/systemd-critical.txt"   2>&1 || true
systemctl list-timers --all --no-pager              > "$OUT/timers.txt"             2>&1 || true
systemctl list-units --type=service --state=running > "$OUT/services-running.txt"   2>&1 || true
ps -eo pid,ppid,etimes,pcpu,pmem,rss,stat,comm,args --sort=-pcpu \
                                                    > "$OUT/ps-start.txt"           2>&1 || true
journalctl -b --no-pager                            > "$OUT/journal-since-boot.txt" 2>&1 || true

# --- continuous sampling, background ----------------------------------------
(
    end=$(( $(date +%s) + SAMPLE_DURATION ))
    while [[ $(date +%s) -lt $end ]]; do
        ts=$(date -u +%FT%TZ)

        # loadavg
        read -r l1 l5 l15 _ < /proc/loadavg
        printf '%s\tload1=%s\tload5=%s\tload15=%s\n' "$ts" "$l1" "$l5" "$l15" >> "$OUT/load.tsv"

        # package-manager lock holders
        for f in /var/lib/rpm/.rpm.lock \
                 /var/lib/rpm/.dbenv.lock \
                 /var/lib/dnf/rpmtransaction.lock \
                 /var/cache/apt/archives/lock \
                 /var/lib/dpkg/lock \
                 /var/lib/dpkg/lock-frontend \
                 /var/lib/apt/lists/lock; do
            if [[ -e "$f" ]]; then
                holders=$(fuser "$f" 2>&1 | tr -s '[:space:]' ' ' | sed 's/^ //;s/ $//')
                if [[ -n "$holders" && "$holders" != *"No process"* ]]; then
                    printf '%s\t%s\t%s\n' "$ts" "$f" "$holders" >> "$OUT/locks.tsv"
                fi
            fi
        done

        # top 5 processes by CPU
        ps -eo pcpu=,comm= --sort=-pcpu | head -5 \
            | awk -v ts="$ts" '{print ts "\t" $1 "\t" $2}' >> "$OUT/top.tsv"

        sleep "$SAMPLE_INTERVAL"
    done
) &
echo $! > "$OUT/sampler.pid"

# vmstat / iostat in the background; they self-terminate after their sample count.
if command -v vmstat >/dev/null 2>&1; then
    vmstat "$SAMPLE_INTERVAL" $((SAMPLE_DURATION / SAMPLE_INTERVAL)) > "$OUT/vmstat.txt" 2>&1 &
fi
if command -v iostat >/dev/null 2>&1; then
    iostat -xz "$SAMPLE_INTERVAL" $((SAMPLE_DURATION / SAMPLE_INTERVAL)) > "$OUT/iostat.txt" 2>&1 &
fi
