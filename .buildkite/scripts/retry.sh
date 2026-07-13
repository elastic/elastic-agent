#!/bin/bash
<<<<<<< HEAD
set -euo pipefail

=======

# retry runs the given command up to $1 times total, with exponential backoff
# between attempts, to protect against transient failures.
# Usage: retry <attempts> <command> [args...]
>>>>>>> 320e5548c (Add retries to network calls in Buildkite CI scripts (#15451))
retry() {
    local retries=$1
    shift

    local count=0
    until "$@"; do
        exit=$?
        wait=$((2 ** count))
        count=$((count + 1))
        if [ $count -lt "$retries" ]; then
            >&2 echo "Retry $count/$retries exited $exit, retrying in $wait seconds..."
            sleep $wait
        else
            >&2 echo "Retry $count/$retries exited $exit, no more retries left."
            return $exit
        fi
    done
    return 0
<<<<<<< HEAD
}
=======
}
>>>>>>> 320e5548c (Add retries to network calls in Buildkite CI scripts (#15451))
