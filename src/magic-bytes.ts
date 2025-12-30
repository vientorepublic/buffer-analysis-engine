/**
 * Represents a magic bytes signature for file type detection.
 * Each element is a byte value (0-255) or null for wildcard matching.
 */
export type MagicBytesSignature = (number | null)[];

/**
 * Collection of magic bytes signatures for various MIME types.
 * Maps MIME types to arrays of byte signatures that identify those file types.
 * null values in signatures act as wildcards.
 */
export const MAGIC_BYTES_SIGNATURES: Record<string, MagicBytesSignature[]> = {
  'image/jpeg': [[0xff, 0xd8, 0xff]],
  'image/png': [[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]],
  'image/gif': [
    [0x47, 0x49, 0x46, 0x38, 0x37, 0x61],
    [0x47, 0x49, 0x46, 0x38, 0x39, 0x61],
  ],
  'image/webp': [[0x52, 0x49, 0x46, 0x46, null, null, null, null, 0x57, 0x45, 0x42, 0x50]],
  'image/bmp': [[0x42, 0x4d]],
  'image/tiff': [
    [0x49, 0x49, 0x2a, 0x00],
    [0x4d, 0x4d, 0x00, 0x2a],
  ],
  'image/svg+xml': [[0x3c, 0x73, 0x76, 0x67]],
  'image/x-icon': [[0x00, 0x00, 0x01, 0x00]],
  'image/heic': [[0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69, 0x63]],
  'image/heif': [[0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69, 0x66]],
  'application/pdf': [[0x25, 0x50, 0x44, 0x46]],
  'application/msword': [[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]],
  'application/rtf': [[0x7b, 0x5c, 0x72, 0x74, 0x66]],
  'application/vnd.ms-excel': [[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]],
  'application/zip': [
    [0x50, 0x4b, 0x03, 0x04],
    [0x50, 0x4b, 0x05, 0x06],
    [0x50, 0x4b, 0x07, 0x08],
  ],
  'application/x-rar-compressed': [[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07]],
  'application/x-7z-compressed': [[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]],
  'application/gzip': [[0x1f, 0x8b]],
  'audio/mpeg': [
    [0xff, 0xfb],
    [0x49, 0x44, 0x33],
  ],
  'audio/wav': [[0x52, 0x49, 0x46, 0x46, null, null, null, null, 0x57, 0x41, 0x56, 0x45]],
  'audio/ogg': [[0x4f, 0x67, 0x67, 0x53]],
  'video/mp4': [[null, null, null, null, 0x66, 0x74, 0x79, 0x70]],
  'video/avi': [[0x52, 0x49, 0x46, 0x46, null, null, null, null, 0x41, 0x56, 0x49, 0x20]],
  'video/quicktime': [
    [null, null, null, null, 0x6d, 0x6f, 0x6f, 0x76],
    [null, null, null, null, 0x6d, 0x64, 0x61, 0x74],
  ],
  'text/html': [
    [0x3c, 0x21, 0x44, 0x4f, 0x43, 0x54, 0x59, 0x50, 0x45],
    [0x3c, 0x68, 0x74, 0x6d, 0x6c],
    [0x3c, 0x48, 0x54, 0x4d, 0x4c],
  ],
  'application/xml': [[0x3c, 0x3f, 0x78, 0x6d, 0x6c]],
  'application/x-msdownload': [[0x4d, 0x5a]],
  'application/x-executable': [[0x7f, 0x45, 0x4c, 0x46]],
  'application/x-mach-binary': [
    [0xfe, 0xed, 0xfa, 0xce],
    [0xfe, 0xed, 0xfa, 0xcf],
    [0xcf, 0xfa, 0xed, 0xfe],
    [0xce, 0xfa, 0xed, 0xfe],
  ],
  'application/java-archive': [[0x50, 0x4b, 0x03, 0x04]],
  'font/woff': [[0x77, 0x4f, 0x46, 0x46]],
  'font/woff2': [[0x77, 0x4f, 0x46, 0x32]],
  'font/ttf': [[0x00, 0x01, 0x00, 0x00]],
  'font/otf': [[0x4f, 0x54, 0x54, 0x4f]],
};

/**
 * Returns a list of all MIME types that have magic bytes signatures.
 * @returns Array of supported MIME type strings
 */
export function getSupportedMimeTypes(): string[] {
  return Object.keys(MAGIC_BYTES_SIGNATURES);
}

/**
 * Gets all magic bytes signatures for a specific MIME type.
 * @param mimeType - MIME type to look up
 * @returns Array of signatures for the MIME type, or empty array if not found
 */
export function getSignaturesForMimeType(mimeType: string): MagicBytesSignature[] {
  return MAGIC_BYTES_SIGNATURES[mimeType] ?? [];
}

/**
 * Checks if a MIME type has any registered magic bytes signatures.
 * @param mimeType - MIME type to check
 * @returns true if signatures exist for this MIME type
 */
export function hasMagicBytesSignature(mimeType: string): boolean {
  return mimeType in MAGIC_BYTES_SIGNATURES;
}

/**
 * Adds a new magic bytes signature for a MIME type.
 * Creates a new entry if the MIME type doesn't exist.
 * @param mimeType - MIME type to add signature for
 * @param signature - Magic bytes signature to add
 */
export function addMagicBytesSignature(mimeType: string, signature: MagicBytesSignature): void {
  if (!MAGIC_BYTES_SIGNATURES[mimeType]) MAGIC_BYTES_SIGNATURES[mimeType] = [];
  MAGIC_BYTES_SIGNATURES[mimeType].push(signature);
}

/**
 * Removes all magic bytes signatures for a MIME type.
 * @param mimeType - MIME type to remove signatures for
 */
export function removeMagicBytesSignatures(mimeType: string): void {
  if (MAGIC_BYTES_SIGNATURES[mimeType]) delete MAGIC_BYTES_SIGNATURES[mimeType];
}

/**
 * Calculates the maximum length among all registered magic bytes signatures.
 * @returns Maximum signature length in bytes
 */
export function getMaxSignatureLength(): number {
  let max = 0;
  for (const sigs of Object.values(MAGIC_BYTES_SIGNATURES)) {
    for (const sig of sigs) {
      max = Math.max(max, sig.length);
    }
  }
  return max;
}
