/** Tolerated difference between the server clock and Apple's or Google's. */
export const CLOCK_SKEW_MS: number = 5 * 60 * 1000

export const ASN1_TAG_CLASS_CONTEXT = 3

/** `extensions [3] EXPLICIT Extensions OPTIONAL` in a TBSCertificate. */
export const CERTIFICATE_EXTENSIONS_TAG = 3
