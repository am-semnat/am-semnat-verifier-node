import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import {
  commonNameOf,
  parseAnchors,
  verifyCertificateChain,
  type TrustAnchors,
} from "./internal/certificate.js";
import {
  signedAttributesOf,
  verifyCmsSignedData,
} from "./internal/cms.js";
import {
  extractSignatures,
  type ExtractedSignature,
} from "./internal/pdf-signatures.js";
import { toArrayBuffer } from "./internal/bytes.js";
import { describe } from "./internal/errors.js";
import { OID_SIGNED_DATA, OID_SIGNING_CERTIFICATE_V2 } from "./internal/oids.js";
import type {
  PadesVerificationInput,
  PadesVerificationResult,
} from "./public-types.js";

const ACCEPTED_SUBFILTERS = new Set([
  "ETSI.CAdES.detached",
  "ETSI.CAdES.attached", // not B-B per spec but accept defensively; keys off CMS shape
  "adbe.pkcs7.detached",
]);
const REJECTED_SUBFILTERS = new Set(["adbe.x509.rsa_sha1"]);

/**
 * Verify every PAdES signature in a signed PDF. Returns one result per
 * signature in document order; never throws on malformed signatures — instead
 * captures the failure under `errors` and `valid: false`. An unsigned PDF
 * returns `[]`. Signatures are verified concurrently — they're independent.
 */
export async function verifyPadesSignatures(
  input: PadesVerificationInput,
): Promise<PadesVerificationResult[]> {
  const sigs = extractSignatures(input.pdf);
  const anchors = parseAnchors(input.trustAnchors);

  return Promise.all(sigs.map((sig) => verifyOne(sig, anchors)));
}

async function verifyOne(
  sig: ExtractedSignature,
  anchors: TrustAnchors,
): Promise<PadesVerificationResult> {
  const errors: string[] = [];
  let signerCommonName: string | null = null;
  let signedAt: Date | null = null;
  let cmsValid = false;
  let chainValid = false;

  if (sig.subFilter && REJECTED_SUBFILTERS.has(sig.subFilter)) {
    errors.push(
      `Rejected legacy /SubFilter ${sig.subFilter} — only PAdES B-B is supported`,
    );
  } else if (sig.subFilter && !ACCEPTED_SUBFILTERS.has(sig.subFilter)) {
    errors.push(`Unsupported /SubFilter ${sig.subFilter}`);
  }

  let signedData: pkijs.SignedData | null = null;
  try {
    signedData = parseSignedDataCms(sig.contents);
  } catch (e) {
    errors.push(describe("CMS parse failed", e));
  }

  if (signedData) {
    if (!hasSigningCertificateV2(signedData)) {
      errors.push(
        "PAdES B-B signature missing required signingCertificateV2 attribute",
      );
    }

    const cmsOutcome = await verifyCmsSignedData(
      signedData,
      toArrayBuffer(sig.signedBytes),
    );
    cmsValid = cmsOutcome.valid;
    signedAt = cmsOutcome.signedAt;
    signerCommonName = commonNameOf(cmsOutcome.signerCert);
    if (!cmsOutcome.valid && cmsOutcome.error) {
      errors.push(cmsOutcome.error);
    }

    try {
      const chainResult = await verifyCertificateChain(
        cmsOutcome.signerCert,
        anchors,
      );
      chainValid = chainResult.valid;
      if (!chainResult.valid && chainResult.error) {
        errors.push(`Certificate chain: ${chainResult.error}`);
      }
    } catch (e) {
      errors.push(describe("Certificate chain error", e));
    }
  }

  const valid = errors.length === 0 && cmsValid && chainValid;

  return {
    valid,
    errors,
    signerCommonName,
    signedAt,
    signatureIndex: sig.signatureIndex,
    fieldName: sig.fieldName,
    byteRange: sig.byteRange,
    coversWholeDocument: sig.coversWholeDocument,
  };
}

function parseSignedDataCms(cmsDer: Uint8Array): pkijs.SignedData {
  const asn1 = asn1js.fromBER(toArrayBuffer(cmsDer));
  if (asn1.offset === -1) {
    throw new Error("Invalid CMS DER encoding");
  }
  const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
  if (contentInfo.contentType !== OID_SIGNED_DATA) {
    throw new Error(
      `CMS contentType is not SignedData (got ${contentInfo.contentType})`,
    );
  }
  return new pkijs.SignedData({ schema: contentInfo.content });
}

function hasSigningCertificateV2(signedData: pkijs.SignedData): boolean {
  return signedAttributesOf(signedData).some(
    (a) => a.type === OID_SIGNING_CERTIFICATE_V2,
  );
}
