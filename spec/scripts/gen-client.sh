#!/bin/sh
# Regenerates crates/batlehub-client from the vendored spec, offline.
# Pipeline: spec/batlehub-v<VERSION>.json -> every spec/patches/*.jq applied
# in lexical order -> openapi-generator (rust/reqwest) -> crate dir.
# The generated crate is committed; CI regenerates it and fails on diff.
set -eu

VERSION="${1:?usage: gen-client.sh <batlehub-version>}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/spec/batlehub-v$VERSION.json"
CRATE="$ROOT/crates/batlehub-client"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

[ -f "$SPEC" ] || { echo "missing $SPEC, run: task gen:spec BATLEHUB_VERSION=$VERSION" >&2; exit 1; }

cp "$SPEC" "$WORK/spec.json"
for patch in "$ROOT"/spec/patches/*.jq; do
  [ -f "$patch" ] || continue
  jq -f "$patch" "$WORK/spec.json" >"$WORK/next.json"
  mv "$WORK/next.json" "$WORK/spec.json"
done

# Keep only the generator output we own; README/docs/.openapi-generator
# metadata churn on every run and add nothing over the spec itself.
rm -rf "$CRATE/src"
# aqua ships the raw jar under the binary name, so it needs `java -jar`.
JAR="${OPENAPI_GENERATOR_JAR:-$(mise which openapi-generator)}"
java -jar "$JAR" generate \
  --input-spec "$WORK/spec.json" \
  --generator-name rust \
  --output "$WORK/out" \
  --config "$ROOT/spec/openapi-generator.yaml" \
  --global-property apiDocs=false,modelDocs=false,apiTests=false,modelTests=false \
  >"$WORK/gen.log" 2>&1 || { cat "$WORK/gen.log" >&2; exit 1; }

mkdir -p "$CRATE"
cp -r "$WORK/out/src" "$CRATE/src"
cp "$ROOT/spec/batlehub-client.Cargo.toml" "$CRATE/Cargo.toml"

# Generated code is not ours to lint; formatting it keeps `cargo fmt --check`
# green and makes the committed output stable for the CI regen-and-diff.
{ printf '%s\n' '#![allow(clippy::all, rustdoc::all)]'; cat "$CRATE/src/lib.rs"; } >"$WORK/lib.rs"
mv "$WORK/lib.rs" "$CRATE/src/lib.rs"
(cd "$ROOT" && cargo fmt -p batlehub-client)
echo "Generated $CRATE from BatleHub v$VERSION"
