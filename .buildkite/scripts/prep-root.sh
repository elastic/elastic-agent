#!/usr/bin/env bash

sudo -E su -c "source /opt/buildkite-agent/hooks/pre-command && source .buildkite/hooks/pre-command && /bin/bash -c \"$@\""