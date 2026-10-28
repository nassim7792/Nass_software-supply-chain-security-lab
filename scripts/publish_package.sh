#!/usr/bin/env bash
# Build the impostor sdist and publish it to the LOCAL registry only.
# This copies the artifact into the pypiserver store (no twine/auth needed).
set -euo pipefail
cd "$(dirname "$0")/.."
PKG="packages/internal-auth-utils"
STORE=".scsim_state/registry_packages"
mkdir -p "$STORE"
rm -rf "$PKG/dist"
python -m build --sdist "$PKG"
cp "$PKG"/dist/*.tar.gz "$STORE"/
echo "Published to local registry store: $STORE"
echo "WARNING: never run 'twine upload' against a real index with this package."
