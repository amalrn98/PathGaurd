#!/usr/bin/env bash
# Fail if any workflow step uses an action that is not pinned to a full 40-hex commit SHA.
# Local actions (./path) and docker:// references are not checked here.
set -euo pipefail
cd "$(dirname "$0")/.."
bad=$(grep -rEn '^\s*-?\s*uses:\s*[^./ ][^@ ]*@' .github/workflows .github/actions 2>/dev/null \
  | grep -vE 'uses:\s*[^@ ]+@[0-9a-f]{40}(\s|$)' || true)
if [ -n "$bad" ]; then
  echo "These action references are not pinned to a full commit SHA:" >&2
  echo "$bad" >&2
  exit 1
fi
echo "all workflow actions are pinned to commit SHAs"
