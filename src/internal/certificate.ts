import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { toArrayBuffer } from "./bytes.js";
import { NODE_HASH_BY_OID, OID_COMMON_NAME } from "./oids.js";

export function nodeHashAlgFromOid(oid: string): string {
  const name = NODE_HASH_BY_OID[oid];
  if (!name) {
    throw new Error(`Unknown hash algorithm OID: ${oid}`);
  }
  return name;
}

export interface TrustAnchors {
  roots: pkijs.Certificate[];
  intermediates: pkijs.Certificate[];
}

export function parseCertificate(der: Uint8Array): pkijs.Certificate {
  const asn1 = asn1js.fromBER(toArrayBuffer(der));
  if (asn1.offset === -1) {
    throw new Error("Failed to parse certificate DER");
  }
  return new pkijs.Certificate({ schema: asn1.result });
}

/**
 * Classify a flat list of trust-anchor certs into roots vs intermediates by
 * self-signedness — issuer DN === subject DN. Mirrors the mobile SDK's
 * `verifyPassiveOffline`, which also accepts a flat list.
 */
export function partitionAnchors(certs: pkijs.Certificate[]): TrustAnchors {
  const roots: pkijs.Certificate[] = [];
  const intermediates: pkijs.Certificate[] = [];
  for (const c of certs) {
    if (c.issuer.isEqual(c.subject)) {
      roots.push(c);
    } else {
      intermediates.push(c);
    }
  }
  return { roots, intermediates };
}

export function parseAnchors(ders: Uint8Array[]): TrustAnchors {
  return partitionAnchors(ders.map(parseCertificate));
}

/**
 * Verify a signer cert chain against caller-supplied trust anchors. Used for
 * eMRTD passive auth (DSC → CSCA Romania) and PAdES signer verification
 * (CitizenCert → Sub-CA → Root-CA). Returns `valid: true` only if the chain
 * builds AND the signer is within its validity period.
 */
export async function verifyCertificateChain(
  signer: pkijs.Certificate,
  anchors: TrustAnchors,
): Promise<{ valid: boolean; error?: string }> {
  const { roots, intermediates } = anchors;

  if (roots.length === 0) {
    return { valid: false, error: "No trusted root CA certificates provided" };
  }

  const now = new Date();
  const notBefore = signer.notBefore.value;
  const notAfter = signer.notAfter.value;
  if (now < notBefore || now > notAfter) {
    return {
      valid: false,
      error: `Signer expired or not yet valid (${notBefore.toISOString()} - ${notAfter.toISOString()})`,
    };
  }

  try {
    const chainEngine = new pkijs.CertificateChainValidationEngine({
      trustedCerts: roots,
      certs: [signer, ...intermediates],
    });
    const result = await chainEngine.verify();
    if (!result.result) {
      return {
        valid: false,
        error: result.resultMessage || "Certificate chain validation failed",
      };
    }
    return { valid: true };
  } catch (e) {
    return {
      valid: false,
      error: `Chain verification error: ${e instanceof Error ? e.message : String(e)}`,
    };
  }
}

export function commonNameOf(cert: pkijs.Certificate): string | null {
  for (const rdn of cert.subject.typesAndValues) {
    if (rdn.type === OID_COMMON_NAME) {
      const v = rdn.value.valueBlock.value as unknown;
      if (typeof v === "string") return v;
    }
  }
  return null;
}
