import { constantTimeEqual, toArrayBuffer } from "./bytes.js";
import { webCryptoHashAlgFromOid } from "./certificate.js";
import type { DataGroupVerificationResult } from "../public-types.js";

/**
 * Verify that the provided raw data group bytes match the hashes signed in the
 * SOD's LDS Security Object. Only the DGs the caller supplies are checked —
 * a SOD that signs hashes for DGs not in `providedDgs` is normal (Romanian
 * CEI cards list DG3/DG7 hashes the mobile SDK never reads), and DGs in the
 * SOD without a hash entry would be a SOD bug, not the caller's problem.
 *
 * A provided DG with no matching SOD hash IS flagged — that suggests the
 * caller's bytes are mislabeled or out of scope.
 */
export async function verifyDataGroupHashes(
  hashAlgorithmOid: string,
  expectedHashes: Map<number, Uint8Array>,
  providedDgs: Map<number, Uint8Array>,
): Promise<DataGroupVerificationResult[]> {
  const algorithm = webCryptoHashAlgFromOid(hashAlgorithmOid);
  const results: DataGroupVerificationResult[] = [];

  for (const [dgNumber, provided] of providedDgs) {
    const expectedHash = expectedHashes.get(dgNumber);
    if (!expectedHash) {
      results.push({
        dgNumber,
        valid: false,
        error: `DG${dgNumber} provided but not present in SOD`,
      });
      continue;
    }
    try {
      const computed = new Uint8Array(
        await crypto.subtle.digest(algorithm, toArrayBuffer(provided)),
      );
      if (constantTimeEqual(computed, expectedHash)) {
        results.push({ dgNumber, valid: true });
      } else {
        results.push({
          dgNumber,
          valid: false,
          error: `DG${dgNumber} hash mismatch`,
        });
      }
    } catch (e) {
      results.push({
        dgNumber,
        valid: false,
        error: `Failed to verify DG${dgNumber}: ${e instanceof Error ? e.message : String(e)}`,
      });
    }
  }

  return results.sort((a, b) => a.dgNumber - b.dgNumber);
}
