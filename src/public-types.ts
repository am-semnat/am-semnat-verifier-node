export interface PassiveVerificationInput {
  rawSod: Uint8Array;
  dataGroups: Record<number, Uint8Array>;
  trustAnchors: Uint8Array[];
}

export interface DataGroupVerificationResult {
  dgNumber: number;
  valid: boolean;
  error?: string;
}

export interface PassiveVerificationResult {
  valid: boolean;
  errors: string[];
  /** SOD CMS signature verified against the embedded DSC. */
  signatureValid: boolean;
  /** DSC chained to a caller-supplied CSCA anchor. */
  certificateValid: boolean;
  /** Every DG hash recomputation matched the SOD-signed value. */
  hashesValid: boolean;
  signerCommonName: string | null;
  signedAt: Date | null;
  dataGroupResults: DataGroupVerificationResult[];
}

export interface PadesVerificationInput {
  pdf: Uint8Array;
  trustAnchors: Uint8Array[];
}

export interface PadesVerificationResult {
  valid: boolean;
  errors: string[];
  signerCommonName: string | null;
  signedAt: Date | null;
  signatureIndex: number;
  fieldName: string | null;
  byteRange: [number, number, number, number];
  coversWholeDocument: boolean;
}
