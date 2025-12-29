export interface BufferAnalysisConfig {
  enableMagicBytesDetection?: boolean;
  enableSuspiciousPatternAnalysis?: boolean;
  maxAnalysisDepth?: number;
  skipLargeFiles?: boolean;
  maxFileSize?: number;
}

export interface BufferAnalysisResult {
  detectedMimeType: string | null;
  hasSuspiciousPatterns: boolean;
  suspiciousPatterns: string[];
  confidence: number;
  analysisSkipped: boolean;
  skipReason?: string;
}
