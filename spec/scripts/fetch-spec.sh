#!/bin/sh
# Downloads BatleHub's OpenAPI spec at a release tag and vendors it as
# spec/batlehub-v<VERSION>.json. BatleHub commits what `batlehub dump-spec`
# writes (utoipa) as ui/openapi.json, versioned with each release.
set -eu

VERSION="${1:?usage: fetch-spec.sh <batlehub-version, e.g. 1.4.0>}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/spec/batlehub-v$VERSION.json"

curl -fsSL "https://raw.githubusercontent.com/batlehub/batlehub/v$VERSION/ui/openapi.json" |
  jq --indent 2 . >"$OUT"

echo "Vendored $OUT"
