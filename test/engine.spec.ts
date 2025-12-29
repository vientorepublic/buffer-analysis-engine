import { describe, it, expect, beforeEach } from "vitest";
import {
  BufferAnalysisEngine,
  analyzeBuffer,
  analyzeStream,
  getBufferAnalysisEngine,
  resetBufferAnalysisEngine,
  MAGIC_BYTES_SIGNATURES,
  getSupportedMimeTypes,
  hasMagicBytesSignature,
  getSignaturesForMimeType,
  addMagicBytesSignature,
  removeMagicBytesSignatures,
  expressBufferAnalysisMiddleware,
} from "../src";

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

  it("analyzeBuffer respects per-call config (uses temporary engine)", () => {
    const global = getBufferAnalysisEngine();
    global.disable();

    const res = analyzeBuffer(Buffer.from([0xff, 0xd8, 0xff]), "temp.jpg", { enableMagicBytesDetection: true });
    expect(res.detectedMimeType).toBe("image/jpeg");

    global.enable();
  });

  it("resetBufferAnalysisEngine resets the singleton", () => {
    const g1 = getBufferAnalysisEngine();
    resetBufferAnalysisEngine();
    const g2 = getBufferAnalysisEngine();
    expect(g1).not.toBe(g2);
  });

  it("detects WEBP with wildcard signature", () => {
    const buf = Buffer.from([0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50]);
    const res = engine.analyzeBuffer(buf, "test.webp");
    expect(res.detectedMimeType).toBe("image/webp");
  });

  it("detects MP4 using wildcard signature", () => {
    const buf = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x66, 0x74, 0x79, 0x70]);
    const res = engine.analyzeBuffer(buf, "test.mp4");
    expect(res.detectedMimeType).toBe("video/mp4");
  });

  it("magic-bytes helpers", () => {
    expect(getSupportedMimeTypes()).toContain("image/png");
    expect(hasMagicBytesSignature("image/png")).toBe(true);
    expect(getSignaturesForMimeType("image/png").length).toBeGreaterThan(0);
  });

  it("can add and remove magic-byte signatures dynamically", () => {
    const testSig = [0x01, 0x02, 0x03];
    addMagicBytesSignature("application/x-test", testSig);
    expect(hasMagicBytesSignature("application/x-test")).toBe(true);
    expect(getSignaturesForMimeType("application/x-test")[0]).toEqual(testSig);
    removeMagicBytesSignatures("application/x-test");
    expect(hasMagicBytesSignature("application/x-test")).toBe(false);
  });

  it("analyzeStream works on small readable streams", async () => {
    const { Readable } = await import("stream");
    const r = Readable.from([Buffer.from([0xff, 0xd8, 0xff, 0xe0])]);
    const res = await engine.analyzeStream(r, "stream.jpg");
    expect(res.detectedMimeType).toBe("image/jpeg");
  });

  it("analyzeStream convenience export works", async () => {
    const { Readable } = await import("stream");
    const r = Readable.from([Buffer.from([0xff, 0xd8, 0xff, 0xe0])]);
    const res = await analyzeStream(r, "stream.jpg");
    expect(res.detectedMimeType).toBe("image/jpeg");
  });

  it("express middleware attaches analysis when body is a buffer", async () => {
    const middleware = expressBufferAnalysisMiddleware({ attachProperty: "ba" });
    const req: any = { body: Buffer.from([0xff, 0xd8, 0xff, 0xe0]) };
    let called = false;
    const next = () => {
      called = true;
    };
    await middleware(req, {}, next);
    expect(called).toBe(true);
    expect(req.ba).toBeTruthy();
    expect(req.ba.detectedMimeType).toBe("image/jpeg");
  });
});
