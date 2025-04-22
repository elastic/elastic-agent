#!/usr/bin/env bash
set -euo pipefail

#
# Install mise and tools listed in .tool-versions
# run 
#
MISE_VERSION="v2025.4.4" 
if ! command -v mise &> /dev/null; then
  # Install mise. See installation guide: https://mise.jdx.dev/installing-mise.html
  curl https://mise.run | sh
  # Add default mise installation to PATH
  export PATH="$HOME/.local/bin:$PATH"
fi 

# Install tools from .tool-versions
mise install 
# Add mise activation to .bashrc (makes tools available directly)

# Activate mise for current session
eval "$(mise activate bash --shims)
