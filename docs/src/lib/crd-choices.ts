// Guided choices of the manifest builder (`<CrdForm>`, @weebo/operator-docs):
// several kinds accept mutually exclusive ways of doing one thing. The
// schema can only say "these are all optional"; this table says which go
// together, so the form asks "how?" first and shows only the matching fields.
//
// Field names are `spec` keys. A kind not listed here gets the plain form.
// Keep them in sync with the CRDs when renaming a field. Empty until the
// managed/external modes of BatleHubLocalInstance land (M1).

import type { CrdChoices } from "@weebo/operator-docs/crd-form";

export const CHOICES: CrdChoices = {};
