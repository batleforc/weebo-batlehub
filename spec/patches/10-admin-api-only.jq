# The operator only calls BatleHub's admin API and `GET /api/v1/me` (the
# token's role): keep those paths, then only the schemas they reach. The
# rest (registry protocols, the console's routes) would be ~300 unused
# operations and their models.
def keep_path: startswith("/api/v1/admin/") or . == "/api/v1/me";

# Every `$ref` target under `x`, as a component schema name.
def refs(x): [x | .. | objects | select(has("$ref")) | ."$ref"
  | select(startswith("#/components/schemas/")) | ltrimstr("#/components/schemas/")]
  | unique;

.paths |= with_entries(select(.key | keep_path))
| . as $spec
| (refs($spec.paths)) as $roots
| [$roots, []]
  | until(.[0] == .[1];
      . as [$now, $_]
      | [($now + refs($now | map($spec.components.schemas[.])) | unique), $now])
  | .[0] as $reachable
| $spec
| .components.schemas |= with_entries(select(.key as $k | $reachable | index($k)))
