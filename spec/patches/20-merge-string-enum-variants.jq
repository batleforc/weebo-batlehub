# utoipa writes a Rust enum mixing unit and data variants as a `oneOf`
# with one single-value string enum per unit variant (FlagKind: "cve",
# "malware"… or {other}). openapi-generator names each of those `String`
# and the generated enum doesn't compile: fold them into one string enum.
def is_string_enum: type == "object" and .type == "string" and has("enum");

.components.schemas |= with_entries(
  if (.value.oneOf // null) != null
     and ([.value.oneOf[] | select(is_string_enum)] | length) > 1
  then .value.oneOf = (
    [{type: "string", enum: [.value.oneOf[] | select(is_string_enum) | .enum[]]}]
    + [.value.oneOf[] | select(is_string_enum | not)]
  )
  else . end
)
