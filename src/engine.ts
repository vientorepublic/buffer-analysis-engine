import { BufferAnalysisConfig, BufferAnalysisResult } from './types';
import { MAGIC_BYTES_SIGNATURES } from './magic-bytes';
import { analyzeSuspiciousPatterns } from './suspicious-patterns';
import { safeObjectAssign, SimpleLogger, silentLogger } from './utils';

/**
 * Default configuration for buffer analysis engine.
 * @internal
 */
const DEFAULT_BUFFER_ANALYSIS_CONFIG: Required<BufferAnalysisConfig> = {
  enableMagicBytesDetection: true,
  enableSuspiciousPatternAnalysis: true,
  maxAnalysisDepth: 1024 * 1024,
  skipLargeFiles: true,
  maxFileSize: 50 * 1024 * 1024,
};

/**
 * Validates the buffer analysis configuration.
 * @param config - Configuration object to validate
 * @throws {Error} If maxAnalysisDepth or maxFileSize is negative
 * @internal
 */
function validateConfig(config: Partial<BufferAnalysisConfig>): void {
  if (config.maxAnalysisDepth !== undefined && config.maxAnalysisDepth < 0) {
    throw new Error('maxAnalysisDepth must be non-negative');
  }
  if (config.maxFileSize !== undefined && config.maxFileSize < 0) {
    throw new Error('maxFileSize must be non-negative');
  }
  // Note: maxAnalysisDepth can be larger than maxFileSize as it controls analysis depth, not file size limit
}

/**
 * Core engine for analyzing buffer content, detecting MIME types and suspicious patterns.
 * Supports both buffer and stream-based analysis with configurable detection options.
 * @example
 * ```typescript
 * const engine = new BufferAnalysisEngine({
 *   enableMagicBytesDetection: true,
 *   maxFileSize: 10 * 1024 * 1024
 * });
 * const result = engine.analyzeBuffer(myBuffer, 'file.jpg');
 * ```
 */
export class BufferAnalysisEngine {
  private readonly config: Required<BufferAnalysisConfig>;
  private logger: SimpleLogger;
  private enabled = true;

  /**
   * Creates a new buffer analysis engine instance.
   * @param config - Optional configuration for buffer analysis behavior
   * @param logger - Optional logger for diagnostic messages (defaults to silent logger)
   * @throws {Error} If configuration validation fails
   */
  constructor(config?: BufferAnalysisConfig, logger?: SimpleLogger) {
    const mergedConfig = { ...DEFAULT_BUFFER_ANALYSIS_CONFIG, ...config };
    validateConfig(mergedConfig);
    this.config = mergedConfig;
    // Default to a silent logger to avoid noisy logs unless the user provides a logger
    this.logger = logger ?? silentLogger;

    const envDisabled = process.env.DISABLE_BUFFER_ANALYSIS === 'true';
    if (envDisabled) {
      this.enabled = false;
      this.logger.warn?.(
        'Buffer analysis disabled by environment variable DISABLE_BUFFER_ANALYSIS',
      );
    }
  }

  /**
   * Enables the buffer analysis engine.
   */
  enable(): void {
    this.enabled = true;
  }

  /**
   * Disables the buffer analysis engine.
   */
  disable(): void {
    this.enabled = false;
  }

  /**
   * Checks if the buffer analysis engine is currently enabled.
   * @returns true if enabled, false otherwise
   */
  isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Analyzes a buffer for MIME type detection and suspicious patterns.
   * @param buffer - The buffer to analyze
   * @param filename - Optional filename for logging context
   * @returns Analysis result containing detected MIME type, suspicious patterns, and confidence score
   * @example
   * ```typescript
   * const buffer = fs.readFileSync('image.jpg');
   * const result = engine.analyzeBuffer(buffer, 'image.jpg');
   * console.log(result.detectedMimeType); // 'image/jpeg'
   * ```
   */
  analyzeBuffer(buffer: Buffer, filename?: string): BufferAnalysisResult {
    if (!this.enabled) {
      return {
        detectedMimeType: null,
        hasSuspiciousPatterns: false,
        suspiciousPatterns: [],
        confidence: 0,
        analysisSkipped: true,
        skipReason: 'Buffer analysis engine is disabled',
      };
    }

    if (!Buffer.isBuffer(buffer)) {
      this.logger.error?.('analyzeBuffer called with non-Buffer input');
      return {
        detectedMimeType: null,
        hasSuspiciousPatterns: false,
        suspiciousPatterns: [],
        confidence: 0,
        analysisSkipped: true,
        skipReason: 'Invalid input: expected Buffer',
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

      this.logger.debug?.(
        `Buffer analysis completed for ${filename ?? 'unknown'}: ${JSON.stringify(result)}`,
      );

      return result;
    } catch (error) {
      this.logger.error?.(
        `Buffer analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
      return {
        detectedMimeType: null,
        hasSuspiciousPatterns: false,
        suspiciousPatterns: [],
        confidence: 0,
        analysisSkipped: true,
        skipReason: 'Analysis failed due to error',
      };
    }
  }

  /**
   * Detects MIME type from buffer using magic bytes signatures.
   * @param buffer - Buffer to analyze
   * @returns Detected MIME type or null if not recognized
   * @private
   */
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

  /**
   * Calculates the maximum length among all magic byte signatures.
   * @returns Maximum signature length in bytes
   * @private
   */
  private getMaxSignatureLength(): number {
    let max = 0;
    for (const sigs of Object.values(MAGIC_BYTES_SIGNATURES)) {
      for (const sig of sigs) {
        max = Math.max(max, sig.length);
      }
    }
    return max;
  }

  /**
   * Analyzes a readable stream for MIME type detection and suspicious patterns.
   * Only reads up to maxAnalysisDepth bytes from the stream.
   * @param readable - Readable stream or async iterable to analyze
   * @param filename - Optional filename for logging context
   * @returns Promise resolving to analysis result
   * @example
   * ```typescript
   * const stream = fs.createReadStream('file.pdf');
   * const result = await engine.analyzeStream(stream, 'file.pdf');
   * ```
   */
  async analyzeStream(
    readable: import('./types').ReadableLike,
    filename?: string,
  ): Promise<BufferAnalysisResult> {
    if (!this.enabled) {
      return {
        detectedMimeType: null,
        hasSuspiciousPatterns: false,
        suspiciousPatterns: [],
        confidence: 0,
        analysisSkipped: true,
        skipReason: 'Buffer analysis engine is disabled',
      };
    }

    if (!readable || typeof readable !== 'object') {
      this.logger.error?.('analyzeStream called with invalid readable input');
      return {
        detectedMimeType: null,
        hasSuspiciousPatterns: false,
        suspiciousPatterns: [],
        confidence: 0,
        analysisSkipped: true,
        skipReason: 'Invalid input: expected readable stream',
      };
    }

    // Pull bytes from stream up to either maxAnalysisDepth or until we have enough for magic detection
    const maxSigLen = this.getMaxSignatureLength();
    const analysisDepth = Math.min(
      this.config.maxAnalysisDepth,
      maxSigLen || this.config.maxAnalysisDepth,
    );

    const chunks: Buffer[] = [];
    let totalLength = 0;

    const asyncIterator = this.toAsyncIterator(readable);
    try {
      for await (const chunk of asyncIterator) {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        chunks.push(buf);
        totalLength += buf.length;

        if (this.config.skipLargeFiles && totalLength > this.config.maxFileSize) {
          // Try to destroy if possible (if readable is a stream with destroy)
          try {
            const maybeStream = readable as NodeJS.ReadableStream & {
              destroy?: (err?: any) => void;
            };
            if (typeof maybeStream.destroy === 'function') maybeStream.destroy();
          } catch {
            // ignore
          }
          return {
            detectedMimeType: null,
            hasSuspiciousPatterns: false,
            suspiciousPatterns: [],
            confidence: 0,
            analysisSkipped: true,
            skipReason: `File too large (${totalLength} bytes > ${this.config.maxFileSize} bytes)`,
          };
        }

        // If we only need magic bytes and we've got enough, we can stop early
        if (
          !this.config.enableSuspiciousPatternAnalysis &&
          this.config.enableMagicBytesDetection &&
          totalLength >= maxSigLen
        )
          break;

        // Stop reading once we have enough bytes for analysis depth
        if (totalLength >= analysisDepth) break;
      }
    } catch (err) {
      this.logger.error?.(
        `Stream read failed: ${err instanceof Error ? err.message : String(err)}`,
      );
      return {
        detectedMimeType: null,
        hasSuspiciousPatterns: false,
        suspiciousPatterns: [],
        confidence: 0,
        analysisSkipped: true,
        skipReason: 'Stream read error',
      };
    }

    const analysisBuffer = Buffer.concat(
      chunks,
      Math.min(totalLength, this.config.maxAnalysisDepth),
    );

    // Reuse analysis from buffer-based method logic
    const result: BufferAnalysisResult = {
      detectedMimeType: null,
      hasSuspiciousPatterns: false,
      suspiciousPatterns: [],
      confidence: 100,
      analysisSkipped: false,
    };

    if (this.config.enableMagicBytesDetection)
      result.detectedMimeType = this.detectMimeTypeFromBuffer(analysisBuffer);
    if (this.config.enableSuspiciousPatternAnalysis) {
      const { hasSuspicious, patterns } = this.analyzeSuspiciousPatterns(analysisBuffer);
      result.hasSuspiciousPatterns = hasSuspicious;
      result.suspiciousPatterns = patterns;
    }

    result.confidence = this.calculateConfidence(analysisBuffer, result);
    this.logger.debug?.(
      `Stream analysis completed for ${filename ?? 'unknown'}: ${JSON.stringify(result)}`,
    );

    return result;
  }

  /**
   * Converts a readable stream to an async iterator.
   * Handles both native async iterables and legacy event-based streams.
   * @param readable - Readable stream to convert
   * @returns Async iterable yielding buffer chunks
   * @private
   */
  private async *toAsyncIterator(readable: import('./types').ReadableLike): AsyncIterable<Buffer> {
    // If it's already an async iterable (e.g., Readable in Node 10+), yield directly
    if (typeof (readable as any)[Symbol.asyncIterator] === 'function') {
      for await (const chunk of readable as AsyncIterable<unknown>) {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as any);
        yield buf;
      }
      return;
    }

    // Fallback for older Readable streams: wrap events
    const stream = readable as NodeJS.ReadableStream;
    const queue: Buffer[] = [];
    let ended = false;
    let error: any = null;

    stream.on('data', (chunk: Buffer) =>
      queue.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)),
    );
    stream.on('end', () => (ended = true));
    stream.on('error', (err: any) => (error = err));

    while (!ended || queue.length > 0) {
      if (error) throw error;
      if (queue.length === 0) {
        // wait for next tick / event
        await new Promise((r) => setTimeout(r, 1));
        continue;
      }
      yield queue.shift() as Buffer;
    }
  }

  /**
   * Checks if buffer matches a magic bytes signature.
   * @param buffer - Buffer to check
   * @param signature - Magic bytes signature (null values are wildcards)
   * @returns true if buffer matches the signature
   * @private
   */
  private matchesMagicBytes(buffer: Buffer, signature: (number | null)[]): boolean {
    if (buffer.length < signature.length) return false;
    for (let i = 0; i < signature.length; i++) {
      const signatureByte = signature[i];
      const bufferByte = buffer[i];
      if (signatureByte !== null && bufferByte !== signatureByte) return false;
    }
    return true;
  }

  /**
   * Analyzes buffer for suspicious patterns such as script tags, eval calls, SQL injection attempts, etc.
   * @param buffer - Buffer to analyze
   * @returns Object containing whether suspicious patterns were found and list of pattern names
   * @private
   */
  private analyzeSuspiciousPatterns(buffer: Buffer): {
    hasSuspicious: boolean;
    patterns: string[];
  } {
    const analysisDepth = Math.min(buffer.length, this.config.maxAnalysisDepth);
    const analysisBuffer = buffer.subarray(0, analysisDepth);

    return analyzeSuspiciousPatterns(analysisBuffer);
  }

  /**
   * Calculates confidence score for the analysis result.
   * Score is reduced if MIME type is not detected, suspicious patterns are found, or buffer is too small.
   * @param buffer - Original buffer
   * @param result - Analysis result
   * @returns Confidence score between 0 and 100
   * @private
   */
  private calculateConfidence(buffer: Buffer, result: BufferAnalysisResult): number {
    let confidence = 100;
    if (!result.detectedMimeType) confidence -= 20;
    if (result.hasSuspiciousPatterns) confidence -= result.suspiciousPatterns.length * 10;
    if (buffer.length < 100) confidence -= 15;
    // Special case: empty buffer should have 0 confidence
    if (buffer.length === 0) confidence = 0;
    return Math.max(0, Math.min(100, confidence));
  }

  /**
   * Returns a copy of the current configuration.
   * @returns Current configuration object
   */
  getConfig(): Required<BufferAnalysisConfig> {
    return { ...this.config };
  }

  /**
   * Updates the engine configuration with new values.
   * Only allowed configuration keys are updated, protecting against prototype pollution.
   * @param newConfig - Partial configuration with values to update
   * @throws {Error} If validation fails for the updated configuration
   */
  updateConfig(newConfig: Partial<BufferAnalysisConfig>): void {
    const allowedConfigKeys: (keyof BufferAnalysisConfig)[] = [
      'enableMagicBytesDetection',
      'enableSuspiciousPatternAnalysis',
      'maxAnalysisDepth',
      'skipLargeFiles',
      'maxFileSize',
    ];

    const tempConfig = { ...this.config };
    safeObjectAssign(
      tempConfig as Record<string, unknown>,
      newConfig as Record<string, unknown>,
      allowedConfigKeys as string[],
    );
    validateConfig(tempConfig);

    safeObjectAssign(
      this.config as Record<string, unknown>,
      newConfig as Record<string, unknown>,
      allowedConfigKeys as string[],
    );
    this.logger.log?.('Buffer analysis configuration updated');
  }

  /**
   * Sets a new logger for the engine.
   * @param logger - Logger instance implementing SimpleLogger interface
   */
  setLogger(logger: SimpleLogger): void {
    this.logger = logger;
  }
}

let globalBufferAnalysisEngine: BufferAnalysisEngine | null = null;

/**
 * Gets or creates a singleton instance of the buffer analysis engine.
 * @param config - Optional configuration for initial creation
 * @param logger - Optional logger for initial creation
 * @returns Global buffer analysis engine instance
 */
export function getBufferAnalysisEngine(
  config?: BufferAnalysisConfig,
  logger?: SimpleLogger,
): BufferAnalysisEngine {
  if (!globalBufferAnalysisEngine) {
    globalBufferAnalysisEngine = new BufferAnalysisEngine(config, logger);
    globalBufferAnalysisEngine.enable();
  }
  return globalBufferAnalysisEngine;
}

/**
 * Convenience function to analyze a buffer using the global engine or a temporary engine with custom config.
 * @param buffer - Buffer to analyze
 * @param filename - Optional filename for logging
 * @param config - Optional configuration (creates temporary engine if provided)
 * @returns Analysis result
 * @example
 * ```typescript
 * const result = analyzeBuffer(myBuffer, 'file.bin');
 * ```
 */
export function analyzeBuffer(
  buffer: Buffer,
  filename?: string,
  config?: BufferAnalysisConfig,
): BufferAnalysisResult {
  // If a per-call config is provided, use a temporary engine so caller config is respected
  if (config) {
    const tempEngine = new BufferAnalysisEngine(config);
    return tempEngine.analyzeBuffer(buffer, filename);
  }

  const engine = getBufferAnalysisEngine();
  return engine.analyzeBuffer(buffer, filename);
}

/**
 * Convenience function to analyze a stream using the global engine or a temporary engine with custom config.
 * @param readable - Readable stream or async iterable to analyze
 * @param filename - Optional filename for logging
 * @param config - Optional configuration (creates temporary engine if provided)
 * @returns Promise resolving to analysis result
 * @example
 * ```typescript
 * const result = await analyzeStream(readStream, 'file.pdf');
 * ```
 */
export async function analyzeStream(
  readable: import('./types').ReadableLike,
  filename?: string,
  config?: BufferAnalysisConfig,
): Promise<BufferAnalysisResult> {
  if (config) {
    const tempEngine = new BufferAnalysisEngine(config);
    return tempEngine.analyzeStream(readable, filename);
  }
  const engine = getBufferAnalysisEngine();
  return engine.analyzeStream(readable, filename);
}

/**
 * Enables or disables the global buffer analysis engine.
 * @param enabled - Whether to enable (true) or disable (false) the engine
 */
export function setBufferAnalysisEnabled(enabled: boolean): void {
  const engine = getBufferAnalysisEngine();
  if (enabled) engine.enable();
  else engine.disable();
}

/**
 * Checks if the global buffer analysis engine is enabled.
 * @returns true if enabled, false otherwise
 */
export function isBufferAnalysisEnabled(): boolean {
  return getBufferAnalysisEngine().isEnabled();
}

/**
 * Resets the global buffer analysis engine instance.
 * Next call to getBufferAnalysisEngine will create a new instance.
 */
export function resetBufferAnalysisEngine(): void {
  globalBufferAnalysisEngine = null;
}
