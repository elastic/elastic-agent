#!/bin/bash

set -euo pipefail
# Unset all variables ending with _SECRET
for var in $(printenv | sed 's;=.*;;' | sort); do
  if [[ "$var" == *_SECRET ]]; then
      unset "$var"
  fi
done