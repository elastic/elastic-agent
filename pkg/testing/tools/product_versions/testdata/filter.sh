#!/bin/bash

# use this script to update the `expected-versions.txt` file when you change `versions.json`
cat versions.json | jq -c '.[][]' | grep 'bltce270507523f4c56' | jq -r '.version_number' > expected-versions.txt
