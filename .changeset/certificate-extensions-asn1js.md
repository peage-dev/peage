---
'@peage/core': patch
---

Attestations no longer fail in apps that already have a newer `@peculiar/asn1-schema`. Core read certificate extensions with `@peculiar/asn1-x509`, and a second copy of `@peculiar/asn1-schema` broke that parsing; it now reads them with `asn1js` and no longer depends on either package. It also refuses a certificate that carries the same extension twice, where it used the first one before. Its `asn1js` and `cbor2` dependencies are now ranges, so apps can share one copy and get fixes without waiting for a Péage release.
