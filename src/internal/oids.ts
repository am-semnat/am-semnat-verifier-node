export const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
export const OID_SIGNING_TIME = "1.2.840.113549.1.9.5";
export const OID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47";
export const OID_COMMON_NAME = "2.5.4.3";

export const OID_SHA1 = "1.3.14.3.2.26";
export const OID_SHA256 = "2.16.840.1.101.3.4.2.1";
export const OID_SHA384 = "2.16.840.1.101.3.4.2.2";
export const OID_SHA512 = "2.16.840.1.101.3.4.2.3";

/**
 * OID → WebCrypto `crypto.subtle.digest` algorithm name. SHA-224 is
 * intentionally absent — WebCrypto does not implement it, and Romanian CEI
 * artifacts in the wild use SHA-256.
 */
export const WEBCRYPTO_HASH_BY_OID: Record<string, string> = {
  [OID_SHA1]: "SHA-1",
  [OID_SHA256]: "SHA-256",
  [OID_SHA384]: "SHA-384",
  [OID_SHA512]: "SHA-512",
};
