import { BufferAnalysisConfig, BufferAnalysisResult } from "./types";
import { MAGIC_BYTES_SIGNATURES } from "./magic-bytes";
import { safeObjectAssign, SimpleLogger, consoleLikeLogger } from "./utils";

const DEFAULT_BUFFER_ANALYSIS_CONFIG: Required<BufferAnalysisConfig> = {
  enableMagicBytesDetection: true,
  enableSuspiciousPatternAnalysis: true,
  maxAnalysisDepth: 1024 * 1024,
  skipLargeFiles: true,
  maxFileSize: 50 * 1024 * 1024,
};

export class BufferAnalysisEngine {
  private readonly config: Required<BufferAnalysisConfig>;
  private readonly logger: SimpleLogger;
  private enabled = true;

  constructor(config?: BufferAnalysisConfig, logger?: SimpleLogger) {
    this.config = { ...DEFAULT_BUFFER_ANALYSIS_CONFIG, ...config };
    this.logger = logger ?? consoleLikeLogger;

    const envDisabled = process.env.DISABLE_BUFFER_ANALYSIS === "true";
    if (envDisabled) {
      this.enabled = false;
      this.logger.warn && this.logger.warn("Buffer analysis disabled by environment variable DISABLE_BUFFER_ANALYSIS");
    }
  }

  enable(): void {
    this.enabled = true;
  }
  disable(): void {
    this.enabled = false;
  }
  isEnabled(): boolean {
    return this.enabled;
  }

  analyzeBuffer(buffer: Buffer, filename?: string): BufferAnalysisResult {
    if (!this.enabled) {
      return {
        detectedMimeType: null,
        hasSuspiciousPatterns: false,
        suspiciousPatterns: [],
        confidence: 0,
        analysisSkipped: true,
        skipReason: "Buffer analysis engine is disabled",
      };
    }

    if (this.config.skipLargeFiles && buffer.length > this.config.maxFileSize) {
      return {
        detectedMimeType: null,
        hasSuspiciousPatterns: false,
        suspiciousPatterns: [],
        confidence: 0,
        analysisSkipped: true,
        skipReason: `File too large (${buffer.length} bytes > ${this.config.maxFileSize} bytes)`,
      };
    }

    const result: BufferAnalysisResult = {
      detectedMimeType: null,
      hasSuspiciousPatterns: false,
      suspiciousPatterns: [],
      confidence: 100,
      analysisSkipped: false,
    };

    try {
      if (this.config.enableMagicBytesDetection) {
        result.detectedMimeType = this.detectMimeTypeFromBuffer(buffer);
      }

      if (this.config.enableSuspiciousPatternAnalysis) {
        const { hasSuspicious, patterns } = this.analyzeSuspiciousPatterns(buffer);
        result.hasSuspiciousPatterns = hasSuspicious;
        result.suspiciousPatterns = patterns;
      }

      result.confidence = this.calculateConfidence(buffer, result);

      this.logger.debug && this.logger.debug(`Buffer analysis completed for ${filename ?? "unknown"}: ${JSON.stringify(result)}`);

      return result;
    } catch (error) {
      this.logger.error && this.logger.error(`Buffer analysis failed: ${error instanceof Error ? error.message : "Unknown error"}`);
      return {
        detectedMimeType: null,
        hasSuspiciousPatterns: false,
        suspiciousPatterns: [],
        confidence: 0,
        analysisSkipped: true,
        skipReason: "Analysis failed due to error",
      };
    }
  }

  private detectMimeTypeFromBuffer(buffer: Buffer): string | null {
    for (const [mimeType, signatures] of Object.entries(MAGIC_BYTES_SIGNATURES)) {
      for (const signature of signatures) {
        if (this.matchesMagicBytes(buffer, signature)) {
          return mimeType;
        }
      }
    }
    return null;
  }

  private matchesMagicBytes(buffer: Buffer, signature: (number | null)[]): boolean {
    if (buffer.length < signature.length) return false;
    for (let i = 0; i < signature.length; i++) {
      const signatureByte = signature.at(i);
      const bufferByte = buffer.at(i);
      if (signatureByte !== null && bufferByte !== signatureByte) return false;
    }
    return true;
  }

  private analyzeSuspiciousPatterns(buffer: Buffer): { hasSuspicious: boolean; patterns: string[] } {
    const analysisDepth = Math.min(buffer.length, this.config.maxAnalysisDepth);
    const analysisBuffer = buffer.subarray(0, analysisDepth);

    const suspiciousPatterns = [
      { pattern: Buffer.from("<script", "utf8"), name: "HTML Script Tag" },
      { pattern: Buffer.from("javascript:", "utf8"), name: "JavaScript Protocol" },
      { pattern: Buffer.from("vbscript:", "utf8"), name: "VBScript Protocol" },
      { pattern: Buffer.from("/JavaScript", "utf8"), name: "PDF JavaScript" },
      { pattern: Buffer.from("alert(", "utf8"), name: "JavaScript Alert" },
      { pattern: Buffer.from("eval(", "utf8"), name: "JavaScript Eval" },
      { pattern: Buffer.from("exec(", "utf8"), name: "Execution Command" },
      { pattern: Buffer.from("system(", "utf8"), name: "System Command" },
      { pattern: Buffer.from("#!/bin/", "utf8"), name: "Shell Shebang" },
      { pattern: Buffer.from("cmd.exe", "utf8"), name: "Windows Command" },
      { pattern: Buffer.from("DROP TABLE", "utf8"), name: "SQL Drop Command" },
      { pattern: Buffer.from("UNION SELECT", "utf8"), name: "SQL Union" },
    ];

    const foundPatterns: string[] = [];
    for (const { pattern, name } of suspiciousPatterns) {
      if (analysisBuffer.includes(pattern)) foundPatterns.push(name);
    }

    return { hasSuspicious: foundPatterns.length > 0, patterns: foundPatterns };
  }

  private calculateConfidence(buffer: Buffer, result: BufferAnalysisResult): number {
    let confidence = 100;
    if (!result.detectedMimeType) confidence -= 20;
    if (result.hasSuspiciousPatterns) confidence -= result.suspiciousPatterns.length * 10;
    if (buffer.length < 100) confidence -= 15;
    return Math.max(0, Math.min(100, confidence));
  }

  getConfig(): Required<BufferAnalysisConfig> {
    return { ...this.config };
  }

  updateConfig(newConfig: Partial<BufferAnalysisConfig>): void {
    const allowedConfigKeys: (keyof BufferAnalysisConfig)[] = [
      "enableMagicBytesDetection",
      "enableSuspiciousPatternAnalysis",
      "maxAnalysisDepth",
      "skipLargeFiles",
      "maxFileSize",
    ];

    safeObjectAssign(this.config as Record<string, unknown>, newConfig as Record<string, unknown>, allowedConfigKeys as string[]);
    this.logger.log && this.logger.log("Buffer analysis configuration updated");
  }
}

let globalBufferAnalysisEngine: BufferAnalysisEngine | null = null;

export function getBufferAnalysisEngine(config?: BufferAnalysisConfig, logger?: SimpleLogger): BufferAnalysisEngine {
  if (!globalBufferAnalysisEngine) {
    globalBufferAnalysisEngine = new BufferAnalysisEngine(config, logger);
    globalBufferAnalysisEngine.enable();
  }
  return globalBufferAnalysisEngine;
}

export function analyzeBuffer(buffer: Buffer, filename?: string, config?: BufferAnalysisConfig): BufferAnalysisResult {
  const engine = getBufferAnalysisEngine(config);
  return engine.analyzeBuffer(buffer, filename);
}

export function setBufferAnalysisEnabled(enabled: boolean): void {
  const engine = getBufferAnalysisEngine();
  if (enabled) engine.enable();
  else engine.disable();
}

export function isBufferAnalysisEnabled(): boolean {
  return getBufferAnalysisEngine().isEnabled();
}

export function logBufferAnalysisStatus(force = false): void {
  if (!force && process.env.NODE_ENV === "production") return;
  const engine = getBufferAnalysisEngine();
  const enabled = engine.isEnabled();
  console.debug("Buffer Analysis Engine Status:");
  console.debug(`- Enabled: ${enabled}`);
  console.debug(`- Environment DISABLE_BUFFER_ANALYSIS: ${process.env.DISABLE_BUFFER_ANALYSIS ?? "N/A"}`);
  console.debug(`- Global instance exists: ${globalBufferAnalysisEngine !== null}`);
}
