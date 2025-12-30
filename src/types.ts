/**
 * Configuration options for the buffer analysis engine.
 */
export interface BufferAnalysisConfig {
  enableMagicBytesDetection?: boolean;
  enableSuspiciousPatternAnalysis?: boolean;
  maxAnalysisDepth?: number;
  skipLargeFiles?: boolean;
  maxFileSize?: number;
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
}

/**
 * Represents a readable source that can be analyzed.
 * Can be either a Node.js ReadableStream or an AsyncIterable of Buffers.
 */
export type ReadableLike = NodeJS.ReadableStream | AsyncIterable<Buffer>;
