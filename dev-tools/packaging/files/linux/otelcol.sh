#!/usr/bin/env bash

BASEDIR=$(dirname "$0")

exec "$BASEDIR/elastic-agent" otel "$@"