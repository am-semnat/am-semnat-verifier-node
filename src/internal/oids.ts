export const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
export const OID_SIGNING_TIME = "1.2.840.113549.1.9.5";
export const OID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47";
export const OID_COMMON_NAME = "2.5.4.3";

export const OID_SHA1 = "1.3.14.3.2.26";
export const OID_SHA224 = "2.16.840.1.101.3.4.2.4";
export const OID_SHA256 = "2.16.840.1.101.3.4.2.1";
export const OID_SHA384 = "2.16.840.1.101.3.4.2.2";
export const OID_SHA512 = "2.16.840.1.101.3.4.2.3";

/** OID → Node `crypto.createHash` algorithm name. */
export const NODE_HASH_BY_OID: Record<string, string> = {
  [OID_SHA1]: "sha1",
  [OID_SHA224]: "sha224",
  [OID_SHA256]: "sha256",
  [OID_SHA384]: "sha384",
  [OID_SHA512]: "sha512",
};
