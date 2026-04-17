#!/usr/bin/env bash
# SDK auto-generation from OpenAPI spec
# Requires: npm -g install @openapitools/openapi-generator-cli
# Usage: ./sdk/generate.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION=$(grep '^version' "$ROOT_DIR/Cargo.toml" | head -1 | sed 's/.*"\(.*\)"/\1/')
SPEC="docs/openapi.yaml"
PYTHON_OUTPUT="sdk/python-generated"
TYPESCRIPT_OUTPUT="sdk/typescript-generated"
TEMP_OPENAPITOOLS=0

if [ ! -e "$ROOT_DIR/openapitools.json" ]; then
  TEMP_OPENAPITOOLS=1
fi

cleanup() {
  rm -rf "$ROOT_DIR/$PYTHON_OUTPUT" "$ROOT_DIR/$TYPESCRIPT_OUTPUT"
  if [ "$TEMP_OPENAPITOOLS" -eq 1 ]; then
    rm -f "$ROOT_DIR/openapitools.json"
  fi
}

trap cleanup EXIT

# The npm wrapper shells out to Java and can split absolute paths that contain
# spaces, so run from the repo root and keep generator paths relative.
cd "$ROOT_DIR"

PYTHON_MODELS_TRACKED=0
if git rev-parse --is-inside-work-tree >/dev/null 2>&1 && git ls-files --error-unmatch sdk/python/wardex/models/__init__.py >/dev/null 2>&1; then
  PYTHON_MODELS_TRACKED=1
fi

if command -v openapi-generator-cli >/dev/null 2>&1 && command -v node >/dev/null 2>&1; then
  OPENAPI_GENERATOR=(node "$(command -v openapi-generator-cli)")
elif command -v npx >/dev/null 2>&1; then
  OPENAPI_GENERATOR=(npx --yes @openapitools/openapi-generator-cli)
else
  echo "openapi-generator-cli not found; install @openapitools/openapi-generator-cli or ensure npx is available" >&2
  exit 1
fi

echo "==> Generating SDKs from OpenAPI spec (v${VERSION})"

# ── Python SDK ────────────────────────────────────────────────────────────────
echo "  → Python SDK"
"${OPENAPI_GENERATOR[@]}" generate \
  -i "$SPEC" \
  -g python \
  -o "$PYTHON_OUTPUT" \
  --additional-properties=packageName=wardex,packageVersion="$VERSION",projectName=wardex \
  --global-property=skipFormModel=false

# Merge generated models into existing SDK
if [ -d "$PYTHON_OUTPUT/wardex/models" ] && [ "$PYTHON_MODELS_TRACKED" -eq 1 ]; then
  cp -r "$PYTHON_OUTPUT/wardex/models/"*.py "sdk/python/wardex/models/" 2>/dev/null || true
  echo "    ✓ Python models updated"
fi

# Update version in pyproject.toml
sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" "sdk/python/pyproject.toml"
rm -f "sdk/python/pyproject.toml.bak"

# ── TypeScript SDK ────────────────────────────────────────────────────────────
echo "  → TypeScript SDK"
"${OPENAPI_GENERATOR[@]}" generate \
  -i "$SPEC" \
  -g typescript-fetch \
  -o "$TYPESCRIPT_OUTPUT" \
  --additional-properties=npmName=@wardex/sdk,npmVersion="$VERSION",supportsES6=true,typescriptThreePlus=true \
  --global-property=skipFormModel=false

# Merge generated types into existing SDK
if [ -d "$TYPESCRIPT_OUTPUT/models" ]; then
  mkdir -p "sdk/typescript/src/generated"
  cp -r "$TYPESCRIPT_OUTPUT/models/"*.ts "sdk/typescript/src/generated/" 2>/dev/null || true
  echo "    ✓ TypeScript models updated"
fi

# Update version in package.json
cd "sdk/typescript"
npm version "$VERSION" --no-git-tag-version --allow-same-version 2>/dev/null || true

echo "==> SDK generation complete (v${VERSION})"
