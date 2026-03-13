/**
 * Configuration options for the buffer analysis engine.
 */
export interface BufferAnalysisConfig {
  enableMagicBytesDetection?: boolean;
  enableSuspiciousPatternAnalysis?: boolean;
  maxAnalysisDepth?: number;
  skipLargeFiles?: boolean;
  maxFileSize?: number;
  suspiciousThreshold?: number;
  mimeTypeSpecificConfig?: Record<string, Partial<BufferAnalysisConfig>>;
}

/**
 * Represents a suspicious pattern with its byte signature and descriptive name.
 */
export interface SuspiciousPattern {
  /** The byte pattern to search for */
  pattern: Buffer;
  /** Human-readable name of the pattern */
  name: string;
  /** Optional MIME types this pattern applies to */
  applicableMimeTypes?: string[];
  /** Optional weight for scoring */
  weight?: number;
  /** Optional regex pattern for more advanced matching */
  regex?: RegExp;
}

/**
 * Result of buffer analysis containing MIME type detection and suspicious pattern findings.
 */
export interface BufferAnalysisResult {
  detectedMimeType: string | null;
  hasSuspiciousPatterns: boolean;
  suspiciousPatterns: string[];
  confidence: number;
  analysisSkipped: boolean;
  skipReason?: string;
  suspiciousScore?: number;
}

/**
 * Represents a readable source that can be analyzed.
 * Can be either a Node.js ReadableStream or an AsyncIterable of Buffers.
 */
export type ReadableLike = NodeJS.ReadableStream | AsyncIterable<Buffer>;
