import { createHash } from "node:crypto";
import { hashAlgorithmFromOid } from "./certificate.js";
import type { DataGroupVerificationResult } from "../public-types.js";

const NODE_HASH_MAP: Record<string, string> = {
  "SHA-1": "sha1",
  "SHA-224": "sha224",
  "SHA-256": "sha256",
  "SHA-384": "sha384",
  "SHA-512": "sha512",
};

function computeHash(data: Uint8Array, algorithm: string): Uint8Array {
  const nodeAlg = NODE_HASH_MAP[algorithm];
  if (!nodeAlg) {
    throw new Error(`Unsupported hash algorithm: ${algorithm}`);
  }
  return new Uint8Array(createHash(nodeAlg).update(data).digest());
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= (a[i] as number) ^ (b[i] as number);
  }
  return result === 0;
}

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
export function verifyDataGroupHashes(
  hashAlgorithmOid: string,
  expectedHashes: Map<number, Uint8Array>,
  providedDgs: Map<number, Uint8Array>,
): DataGroupVerificationResult[] {
  const algorithm = hashAlgorithmFromOid(hashAlgorithmOid);
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
      const computed = computeHash(provided, algorithm);
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
