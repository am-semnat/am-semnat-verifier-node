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
