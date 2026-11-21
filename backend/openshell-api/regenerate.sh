#!/bin/sh
# Regenerates src/generated/ from proto/ (README.md). From anywhere:
#   sh backend/openshell-api/regenerate.sh
set -eu
dir="$(cd "$(dirname "$0")" && pwd)"
sh "$dir/codegen/fetch-protoc.sh" >/dev/null
rm -rf "$dir/src/generated"
mkdir -p "$dir/src/generated"
PROTOC="$dir/codegen/.protoc/bin/protoc" \
PROTOC_INCLUDE="$dir/codegen/.protoc/include" \
  cargo run --quiet --locked --manifest-path "$dir/codegen/Cargo.toml"
