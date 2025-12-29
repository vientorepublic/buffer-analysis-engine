import { describe, it, expect, beforeEach } from "vitest";
import { BufferAnalysisEngine, analyzeBuffer, getBufferAnalysisEngine, MAGIC_BYTES_SIGNATURES } from "../src";

describe("BufferAnalysisEngine basic behavior", () => {
  let engine: BufferAnalysisEngine;

  beforeEach(() => {
    engine = new BufferAnalysisEngine();
    engine.enable();
  });

  it("detects JPEG magic bytes", () => {
    const buf = Buffer.from([0xff, 0xd8, 0xff, 0xe0]);
    const result = engine.analyzeBuffer(buf, "test.jpg");
    expect(result.detectedMimeType).toBe("image/jpeg");
  });

  it("detects suspicious script patterns", () => {
    const buf = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.from("<script>alert(1)</script>")]);
    const result = engine.analyzeBuffer(buf, "test.jpg");
    expect(result.hasSuspiciousPatterns).toBe(true);
  });

  it("skips large files when configured", () => {
    const smallCfgEngine = new BufferAnalysisEngine({ maxFileSize: 10, skipLargeFiles: true });
    const bigBuf = Buffer.alloc(100, 0x41);
    const result = smallCfgEngine.analyzeBuffer(bigBuf, "big.dat");
    expect(result.analysisSkipped).toBe(true);
  });

  it("global instance behavior", () => {
    const g1 = getBufferAnalysisEngine();
    const g2 = getBufferAnalysisEngine();
    expect(g1).toBe(g2);
    g1.disable();
    expect(g2.isEnabled()).toBe(false);
    g1.enable();
    expect(g2.isEnabled()).toBe(true);
  });

  it("analyzeBuffer convenience function", () => {
    const buf = Buffer.from([0xff, 0xd8, 0xff]);
    const res = analyzeBuffer(buf, "test.jpg");
    expect(res.detectedMimeType).toBe("image/jpeg");
  });
});
