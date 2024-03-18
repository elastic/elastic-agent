#!/bin/bash

cat versions.json | jq -c '.[][]' | grep 'bltce270507523f4c56' | jq -r '.version_number'
