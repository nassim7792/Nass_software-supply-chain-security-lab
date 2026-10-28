#!/usr/bin/env bash
# Start the local private PyPI index (pypiserver) for the lab.
# Anonymous upload/download is enabled ON PURPOSE because this is a localhost-only
# teaching registry. Never expose it beyond 127.0.0.1.
set -euo pipefail
cd "$(dirname "$0")/.."
STORE=".scsim_state/registry_packages"
mkdir -p "$STORE"
exec python -m pypiserver run -p 8080 -i 127.0.0.1 -a . -P . "$STORE"
