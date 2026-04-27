/**
 * Slice a `Uint8Array` view's underlying buffer into a fresh `ArrayBuffer`.
 * Required for `asn1js.fromBER` and other pkijs entry points that expect a
 * standalone buffer rather than a view.
 */
export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
}

/**
 * Constant-time byte comparison. Replaces Node's `timingSafeEqual` with a
 * portable implementation so the package runs unchanged in browsers, edge
 * runtimes, and Node 20+.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
