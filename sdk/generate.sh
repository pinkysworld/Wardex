#!/usr/bin/env bash
# SDK auto-generation from OpenAPI spec
# Requires: npm -g install @openapitools/openapi-generator-cli
# Usage: ./sdk/generate.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SPEC="$ROOT_DIR/docs/openapi.yaml"
VERSION=$(grep '^version' "$ROOT_DIR/Cargo.toml" | head -1 | sed 's/.*"\(.*\)"/\1/')

echo "==> Generating SDKs from OpenAPI spec (v${VERSION})"

# ── Python SDK ────────────────────────────────────────────────────────────────
echo "  → Python SDK"
openapi-generator-cli generate \
  -i "$SPEC" \
  -g python \
  -o "$SCRIPT_DIR/python-generated" \
  --additional-properties=packageName=wardex,packageVersion="$VERSION",projectName=wardex \
  --global-property=skipFormModel=false \
  2>/dev/null

# Merge generated models into existing SDK
if [ -d "$SCRIPT_DIR/python-generated/wardex/models" ]; then
  mkdir -p "$SCRIPT_DIR/python/wardex/models"
  cp -r "$SCRIPT_DIR/python-generated/wardex/models/"*.py "$SCRIPT_DIR/python/wardex/models/" 2>/dev/null || true
  echo "    ✓ Python models updated"
fi
rm -rf "$SCRIPT_DIR/python-generated"

# Update version in pyproject.toml
sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" "$SCRIPT_DIR/python/pyproject.toml"
rm -f "$SCRIPT_DIR/python/pyproject.toml.bak"

# ── TypeScript SDK ────────────────────────────────────────────────────────────
echo "  → TypeScript SDK"
openapi-generator-cli generate \
  -i "$SPEC" \
  -g typescript-fetch \
  -o "$SCRIPT_DIR/typescript-generated" \
  --additional-properties=npmName=@wardex/sdk,npmVersion="$VERSION",supportsES6=true,typescriptThreePlus=true \
  --global-property=skipFormModel=false \
  2>/dev/null

# Merge generated types into existing SDK
if [ -d "$SCRIPT_DIR/typescript-generated/models" ]; then
  mkdir -p "$SCRIPT_DIR/typescript/src/generated"
  cp -r "$SCRIPT_DIR/typescript-generated/models/"*.ts "$SCRIPT_DIR/typescript/src/generated/" 2>/dev/null || true
  echo "    ✓ TypeScript models updated"
fi
rm -rf "$SCRIPT_DIR/typescript-generated"

# Update version in package.json
cd "$SCRIPT_DIR/typescript"
npm version "$VERSION" --no-git-tag-version --allow-same-version 2>/dev/null || true

echo "==> SDK generation complete (v${VERSION})"
