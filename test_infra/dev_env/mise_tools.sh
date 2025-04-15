#!/usr/bin/env bash
set -euo pipefail

curl https://mise.run | sh
export PATH="$HOME/.local/bin:$PATH"
mise install
echo 'eval "$(~/mise activate bash)"' >> ~/.bashrc
eval "$(mise activate bash --shims)"

go version