import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  BufferAnalysisEngine,
  analyzeBuffer,
  analyzeStream,
  getBufferAnalysisEngine,
  resetBufferAnalysisEngine,
  getSupportedMimeTypes,
  hasMagicBytesSignature,
  getSignaturesForMimeType,
  addMagicBytesSignature,
  removeMagicBytesSignatures,
  expressBufferAnalysisMiddleware,
  koaBufferAnalysisMiddleware,
  setBufferAnalysisEnabled,
  isBufferAnalysisEnabled,
  analyzeSuspiciousPatterns,
  getAllSuspiciousPatternNames,
  getSuspiciousPatternCount,
  getPatternsByCategory,
  SUSPICIOUS_PATTERNS,
} from '../src';

describe('BufferAnalysisEngine basic behavior', () => {
  let engine: BufferAnalysisEngine;

  beforeEach(() => {
    engine = new BufferAnalysisEngine();
    engine.enable();
  });

  it('detects JPEG magic bytes', () => {
    const buf = Buffer.from([0xff, 0xd8, 0xff, 0xe0]);
    const result = engine.analyzeBuffer(buf, 'test.jpg');
    expect(result.detectedMimeType).toBe('image/jpeg');
  });

  it('detects suspicious script patterns', () => {
    const buf = Buffer.concat([
      Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
      Buffer.from('<script>alert(1)</script>'),
    ]);
    const result = engine.analyzeBuffer(buf, 'test.jpg');
    expect(result.hasSuspiciousPatterns).toBe(true);
  });

  it('detects JavaScript protocol', () => {
    const buf = Buffer.from('javascript:alert(1)');
    const result = engine.analyzeBuffer(buf, 'test.txt');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('JavaScript Protocol');
  });

  it('detects VBScript protocol', () => {
    const buf = Buffer.from('vbscript:msgbox(1)');
    const result = engine.analyzeBuffer(buf, 'test.txt');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('VBScript Protocol');
  });

  it('detects PDF JavaScript', () => {
    const buf = Buffer.from('/JavaScript alert(1)');
    const result = engine.analyzeBuffer(buf, 'test.pdf');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('PDF JavaScript');
  });

  it('detects JavaScript alert', () => {
    const buf = Buffer.from('alert("test")');
    const result = engine.analyzeBuffer(buf, 'test.js');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('JavaScript Alert');
  });

  it('detects JavaScript eval', () => {
    const buf = Buffer.from('eval("code")');
    const result = engine.analyzeBuffer(buf, 'test.js');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('JavaScript Eval');
  });

  it('detects execution command', () => {
    const buf = Buffer.from('exec("ls")');
    const result = engine.analyzeBuffer(buf, 'test.php');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('Execution Command');
  });

  it('detects system command', () => {
    const buf = Buffer.from('system("rm -rf")');
    const result = engine.analyzeBuffer(buf, 'test.php');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('System Command');
  });

  it('detects shell shebang', () => {
    const buf = Buffer.from('#!/bin/bash\necho hello');
    const result = engine.analyzeBuffer(buf, 'test.sh');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('Shell Shebang');
  });

  it('detects Windows command', () => {
    const buf = Buffer.from('cmd.exe /c dir');
    const result = engine.analyzeBuffer(buf, 'test.bat');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('Windows Command');
  });

  it('detects SQL DROP TABLE', () => {
    const buf = Buffer.from('DROP TABLE users');
    const result = engine.analyzeBuffer(buf, 'test.sql');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('SQL Drop Command');
  });

  it('detects SQL UNION SELECT', () => {
    const buf = Buffer.from('UNION SELECT * FROM users');
    const result = engine.analyzeBuffer(buf, 'test.sql');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('SQL Union');
  });

  // Extended pattern tests
  it('detects HTML script close tag', () => {
    const buf = Buffer.from('</script>');
    const result = engine.analyzeBuffer(buf, 'test.html');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('HTML Script Close Tag');
  });

  it('detects HTML iframe tag', () => {
    const buf = Buffer.from('<iframe src="evil.com">');
    const result = engine.analyzeBuffer(buf, 'test.html');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('HTML Iframe Tag');
  });

  it('detects HTML onload event', () => {
    const buf = Buffer.from('<img onload="alert(1)">');
    const result = engine.analyzeBuffer(buf, 'test.html');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('HTML Onload Event');
  });

  it('detects JavaScript cookie access', () => {
    const buf = Buffer.from('document.cookie="session=123"');
    const result = engine.analyzeBuffer(buf, 'test.js');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('JavaScript Cookie Access');
  });

  it('detects JavaScript confirm', () => {
    const buf = Buffer.from('confirm("Are you sure?")');
    const result = engine.analyzeBuffer(buf, 'test.js');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('JavaScript Confirm');
  });

  it('detects JavaScript Function constructor', () => {
    const buf = Buffer.from('new Function("alert(1)")');
    const result = engine.analyzeBuffer(buf, 'test.js');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('JavaScript Function Constructor');
  });

  it('detects Node.js child process', () => {
    const buf = Buffer.from("require('child_process').exec");
    const result = engine.analyzeBuffer(buf, 'test.js');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('Node.js Child Process');
  });

  it('detects shell exec command', () => {
    const buf = Buffer.from('shell_exec("ls -la")');
    const result = engine.analyzeBuffer(buf, 'test.php');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('Shell Exec Command');
  });

  it('detects PowerShell', () => {
    const buf = Buffer.from('powershell -c "Get-Process"');
    const result = engine.analyzeBuffer(buf, 'test.ps1');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('PowerShell');
  });

  it('detects SQL DROP DATABASE', () => {
    const buf = Buffer.from('DROP DATABASE test');
    const result = engine.analyzeBuffer(buf, 'test.sql');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('SQL Drop Database');
  });

  it('detects SQL TRUNCATE TABLE', () => {
    const buf = Buffer.from('TRUNCATE TABLE users');
    const result = engine.analyzeBuffer(buf, 'test.sql');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('SQL Truncate Table');
  });

  it('detects SQL SELECT ALL', () => {
    const buf = Buffer.from('SELECT * FROM users');
    const result = engine.analyzeBuffer(buf, 'test.sql');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('SQL Select All');
  });

  it('detects SQL comment', () => {
    const buf = Buffer.from('SELECT * FROM users -- comment');
    const result = engine.analyzeBuffer(buf, 'test.sql');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('SQL Comment');
  });

  it('detects SQL OR injection', () => {
    const buf = Buffer.from('OR 1=1 --');
    const result = engine.analyzeBuffer(buf, 'test.sql');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('SQL OR Injection');
  });

  it('detects PHP open tag', () => {
    const buf = Buffer.from('<?php echo "hello"; ?>');
    const result = engine.analyzeBuffer(buf, 'test.php');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('PHP Open Tag');
  });

  it('detects PHP include', () => {
    const buf = Buffer.from('include("config.php")');
    const result = engine.analyzeBuffer(buf, 'test.php');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('PHP Include');
  });

  it('detects Python subprocess', () => {
    const buf = Buffer.from('import subprocess; subprocess.call(["ls"])');
    const result = engine.analyzeBuffer(buf, 'test.py');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('Python Subprocess');
  });

  it('detects base64 encoding', () => {
    const buf = Buffer.from('base64_decode("SGVsbG8=")');
    const result = engine.analyzeBuffer(buf, 'test.php');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('Base64 Encoding');
  });

  it('detects command separator', () => {
    const buf = Buffer.from('ls; rm -rf /');
    const result = engine.analyzeBuffer(buf, 'test.sh');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('Command Separator');
  });

  it('detects pipe operator', () => {
    const buf = Buffer.from('cat file.txt | grep "pattern"');
    const result = engine.analyzeBuffer(buf, 'test.sh');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('Pipe Operator');
  });

  it('detects Unix passwd file', () => {
    const buf = Buffer.from('/etc/passwd');
    const result = engine.analyzeBuffer(buf, 'test.txt');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('Unix Passwd File');
  });

  it('detects directory traversal', () => {
    const buf = Buffer.from('../../../etc/passwd');
    const result = engine.analyzeBuffer(buf, 'test.txt');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('Directory Traversal');
  });

  // Edge case tests
  it('handles empty buffer', () => {
    const buf = Buffer.alloc(0);
    const result = engine.analyzeBuffer(buf, 'empty.txt');
    expect(result.hasSuspiciousPatterns).toBe(false);
    expect(result.suspiciousPatterns).toEqual([]);
    expect(result.confidence).toBe(0); // Small buffer penalty
  });

  it('handles buffer with only null bytes', () => {
    const buf = Buffer.alloc(100, 0);
    const result = engine.analyzeBuffer(buf, 'nulls.bin');
    expect(result.hasSuspiciousPatterns).toBe(false);
    expect(result.detectedMimeType).toBe(null);
  });

  it('handles very large buffer without patterns', () => {
    const buf = Buffer.alloc(1024 * 1024, 0x41); // 1MB of 'A's
    const result = engine.analyzeBuffer(buf, 'large.txt');
    expect(result.hasSuspiciousPatterns).toBe(false);
    expect(result.analysisSkipped).toBe(false);
  });

  it('handles buffer with unicode characters', () => {
    const buf = Buffer.from('🚀 Hello 世界 🌍 <script>alert("test")</script>', 'utf8');
    const result = engine.analyzeBuffer(buf, 'unicode.txt');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('HTML Script Tag');
  });

  it('handles case insensitive pattern matching', () => {
    // Note: Pattern matching is case-sensitive for security reasons
    const buf = Buffer.from('DROP table users');
    const result = engine.analyzeBuffer(buf, 'test.sql');
    expect(result.hasSuspiciousPatterns).toBe(false); // Case-sensitive matching
  });

  it('handles patterns with whitespace', () => {
    // Note: Pattern matching requires exact byte sequence
    const buf = Buffer.from('DROP   TABLE    users');
    const result = engine.analyzeBuffer(buf, 'test.sql');
    expect(result.hasSuspiciousPatterns).toBe(false); // Exact matching, no whitespace tolerance
  });

  it('does not detect partial matches', () => {
    const buf = Buffer.from('DROP_TABLE'); // underscore instead of space
    const result = engine.analyzeBuffer(buf, 'test.txt');
    expect(result.hasSuspiciousPatterns).toBe(false);
  });

  it('handles multiple overlapping patterns', () => {
    const buf = Buffer.from('<script>eval("alert(1)")</script>');
    const result = engine.analyzeBuffer(buf, 'test.html');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns.length).toBeGreaterThan(1);
    expect(result.suspiciousPatterns).toContain('HTML Script Tag');
    expect(result.suspiciousPatterns).toContain('JavaScript Eval');
  });

  it('handles binary data with embedded patterns', () => {
    const binaryData = Buffer.from([0x00, 0x01, 0x02]);
    const scriptData = Buffer.from('<script>');
    const buf = Buffer.concat([binaryData, scriptData]);
    const result = engine.analyzeBuffer(buf, 'binary.dat');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('HTML Script Tag');
  });

  it('handles patterns at buffer boundaries', () => {
    const buf = Buffer.from('<script>alert(1)</script>');
    const result = engine.analyzeBuffer(buf, 'test.html');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('HTML Script Tag');
  });

  it('handles patterns split across buffer chunks', () => {
    // This tests the limitation - patterns split across chunks won't be detected
    const chunk1 = Buffer.from('<scrip');
    const chunk2 = Buffer.from('t>alert(1)</script>');
    const buf = Buffer.concat([chunk1, chunk2]);
    const result = engine.analyzeBuffer(buf, 'test.html');
    // The pattern '<script' should still be detected in chunk1
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('HTML Script Tag');
  });

  it('handles URL-encoded malicious content', () => {
    const buf = Buffer.from('%3Cscript%3Ealert%281%29%3C%2Fscript%3E');
    const result = engine.analyzeBuffer(buf, 'test.txt');
    // URL encoding should not hide the script tag pattern
    expect(result.hasSuspiciousPatterns).toBe(false); // %3C is not '<'
  });

  it('handles base64 encoded content', () => {
    const maliciousJs = Buffer.from('<script>alert(1)</script>');
    const base64Encoded = maliciousJs.toString('base64');
    const buf = Buffer.from(base64Encoded);
    const result = engine.analyzeBuffer(buf, 'test.b64');
    // Base64 encoded content should not match text patterns
    expect(result.hasSuspiciousPatterns).toBe(false);
  });

  it('handles mixed encoding scenarios', () => {
    const buf = Buffer.from('data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==');
    const result = engine.analyzeBuffer(buf, 'test.txt');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('Data URL HTML');
  });

  it('handles extremely long patterns', () => {
    const longPattern = 'A'.repeat(1000) + '<script>alert(1)</script>';
    const buf = Buffer.from(longPattern);
    const result = engine.analyzeBuffer(buf, 'long.txt');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('HTML Script Tag');
  });

  it('respects analysis depth limit for patterns', () => {
    const engine = new BufferAnalysisEngine({ maxAnalysisDepth: 50 });
    const buf = Buffer.concat([
      Buffer.alloc(60, 0x41), // Fill up to analysis depth
      Buffer.from('<script>alert(1)</script>'), // This should not be analyzed
    ]);
    const result = engine.analyzeBuffer(buf, 'test.dat');
    expect(result.hasSuspiciousPatterns).toBe(false);
  });

  it('handles concurrent pattern detection', () => {
    const patterns = [
      '<script>alert(1)</script>',
      'eval("code")',
      'DROP TABLE users',
      'system("rm -rf")',
    ];
    const buf = Buffer.from(patterns.join('\n'));
    const result = engine.analyzeBuffer(buf, 'malicious.txt');
    expect(result.hasSuspiciousPatterns).toBe(true);
    // Multiple patterns may match within each line due to overlapping signatures
    expect(result.suspiciousPatterns.length).toBeGreaterThanOrEqual(4);
  });

  it('handles multiple suspicious patterns', () => {
    const buf = Buffer.from('<script>alert(1)</script> eval("code") DROP TABLE test');
    const result = engine.analyzeBuffer(buf, 'test.txt');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns.length).toBeGreaterThan(1);
  });

  it('skips large files when configured', () => {
    const smallCfgEngine = new BufferAnalysisEngine({ maxFileSize: 10, skipLargeFiles: true });
    const bigBuf = Buffer.alloc(100, 0x41);
    const result = smallCfgEngine.analyzeBuffer(bigBuf, 'big.dat');
    expect(result.analysisSkipped).toBe(true);
  });

  it('does not skip large files when skipLargeFiles is false', () => {
    const engine = new BufferAnalysisEngine({ maxFileSize: 10, skipLargeFiles: false });
    const bigBuf = Buffer.alloc(100, 0x41);
    const result = engine.analyzeBuffer(bigBuf, 'big.dat');
    expect(result.analysisSkipped).toBe(false);
  });

  it('respects maxAnalysisDepth for suspicious pattern analysis', () => {
    const engine = new BufferAnalysisEngine({ maxAnalysisDepth: 10 });
    const buf = Buffer.concat([Buffer.alloc(20, 0x41), Buffer.from('<script>alert(1)</script>')]);
    const result = engine.analyzeBuffer(buf, 'test.dat');
    // Since analysis depth is 10, it shouldn't detect the script at position 20
    expect(result.hasSuspiciousPatterns).toBe(false);
  });

  it('disables magic bytes detection when configured', () => {
    const engine = new BufferAnalysisEngine({ enableMagicBytesDetection: false });
    const buf = Buffer.from([0xff, 0xd8, 0xff, 0xe0]);
    const result = engine.analyzeBuffer(buf, 'test.jpg');
    expect(result.detectedMimeType).toBe(null);
  });

  it('disables suspicious pattern analysis when configured', () => {
    const engine = new BufferAnalysisEngine({ enableSuspiciousPatternAnalysis: false });
    const buf = Buffer.from('<script>alert(1)</script>');
    const result = engine.analyzeBuffer(buf, 'test.html');
    expect(result.hasSuspiciousPatterns).toBe(false);
  });

  it('updates configuration dynamically', () => {
    const engine = new BufferAnalysisEngine();
    engine.updateConfig({ enableMagicBytesDetection: false });
    const buf = Buffer.from([0xff, 0xd8, 0xff, 0xe0]);
    const result = engine.analyzeBuffer(buf, 'test.jpg');
    expect(result.detectedMimeType).toBe(null);
  });

  it('ignores invalid config keys in updateConfig', () => {
    const engine = new BufferAnalysisEngine();
    // This should not throw and should ignore invalid keys
    engine.updateConfig({ invalidKey: 'value' } as any);
    expect(engine.getConfig().enableMagicBytesDetection).toBe(true);
  });

  it('validates config values in constructor', () => {
    expect(() => new BufferAnalysisEngine({ maxAnalysisDepth: -1 })).toThrow(
      'maxAnalysisDepth must be non-negative',
    );
    expect(() => new BufferAnalysisEngine({ maxFileSize: -1 })).toThrow(
      'maxFileSize must be non-negative',
    );
    // maxAnalysisDepth can be larger than maxFileSize
    expect(
      () => new BufferAnalysisEngine({ maxAnalysisDepth: 100, maxFileSize: 50 }),
    ).not.toThrow();
  });

  it('validates config values in updateConfig', () => {
    const engine = new BufferAnalysisEngine();
    expect(() => engine.updateConfig({ maxAnalysisDepth: -1 })).toThrow(
      'maxAnalysisDepth must be non-negative',
    );
    expect(() => engine.updateConfig({ maxFileSize: -1 })).toThrow(
      'maxFileSize must be non-negative',
    );
    // maxAnalysisDepth can be larger than maxFileSize
    expect(() => engine.updateConfig({ maxAnalysisDepth: 100, maxFileSize: 50 })).not.toThrow();
  });

  it('handles edge case config values', () => {
    const engine = new BufferAnalysisEngine({ maxAnalysisDepth: 0, maxFileSize: 0 });
    const buf = Buffer.from([0xff, 0xd8, 0xff, 0xe0]);
    const result = engine.analyzeBuffer(buf, 'test.jpg');
    expect(result.detectedMimeType).toBe(null); // No analysis due to depth 0
    expect(result.hasSuspiciousPatterns).toBe(false);
  });

  it('global instance behavior', () => {
    const g1 = getBufferAnalysisEngine();
    const g2 = getBufferAnalysisEngine();
    expect(g1).toBe(g2);
    g1.disable();
    expect(g2.isEnabled()).toBe(false);
    g1.enable();
    expect(g2.isEnabled()).toBe(true);
  });

  it('default logger is silent and setLogger works', () => {
    const engine = new BufferAnalysisEngine();

    const debugSpy = vi.spyOn(console, 'debug');
    engine.analyzeBuffer(Buffer.from([0xff, 0xd8, 0xff]), 'no-log.jpg');
    expect(debugSpy).not.toHaveBeenCalled();

    const mockLogger = { debug: vi.fn(), log: vi.fn(), warn: vi.fn(), error: vi.fn() };
    engine.setLogger(mockLogger as any);
    engine.analyzeBuffer(Buffer.from([0xff, 0xd8, 0xff]), 'with-log.jpg');
    expect(mockLogger.debug).toHaveBeenCalled();

    debugSpy.mockRestore();
  });

  it('analyzeBuffer convenience function', () => {
    const buf = Buffer.from([0xff, 0xd8, 0xff]);
    const res = analyzeBuffer(buf, 'test.jpg');
    expect(res.detectedMimeType).toBe('image/jpeg');
  });

  it('analyzeBuffer respects per-call config (uses temporary engine)', () => {
    const global = getBufferAnalysisEngine();
    global.disable();

    const res = analyzeBuffer(Buffer.from([0xff, 0xd8, 0xff]), 'temp.jpg', {
      enableMagicBytesDetection: true,
    });
    expect(res.detectedMimeType).toBe('image/jpeg');

    global.enable();
  });

  it('resetBufferAnalysisEngine resets the singleton', () => {
    const g1 = getBufferAnalysisEngine();
    resetBufferAnalysisEngine();
    const g2 = getBufferAnalysisEngine();
    expect(g1).not.toBe(g2);
  });

  it('setBufferAnalysisEnabled and isBufferAnalysisEnabled work', () => {
    const initial = isBufferAnalysisEnabled();
    setBufferAnalysisEnabled(false);
    expect(isBufferAnalysisEnabled()).toBe(false);
    setBufferAnalysisEnabled(true);
    expect(isBufferAnalysisEnabled()).toBe(initial);
  });

  it('logger warns when disabled by environment variable', () => {
    const originalEnv = process.env.DISABLE_BUFFER_ANALYSIS;
    process.env.DISABLE_BUFFER_ANALYSIS = 'true';

    const mockLogger = { debug: vi.fn(), log: vi.fn(), warn: vi.fn(), error: vi.fn() };
    const engine = new BufferAnalysisEngine({}, mockLogger);

    expect(engine.isEnabled()).toBe(false);
    expect(mockLogger.warn).toHaveBeenCalledWith(
      'Buffer analysis disabled by environment variable DISABLE_BUFFER_ANALYSIS',
    );

    // Restore
    if (originalEnv === undefined) {
      delete process.env.DISABLE_BUFFER_ANALYSIS;
    } else {
      process.env.DISABLE_BUFFER_ANALYSIS = originalEnv;
    }
  });

  it('calculates confidence correctly', () => {
    const engine = new BufferAnalysisEngine();

    // High confidence: detected MIME, no suspicious patterns, large buffer
    const buf1 = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(200, 0x41)]);
    const res1 = engine.analyzeBuffer(buf1, 'test.jpg');
    expect(res1.confidence).toBe(100);

    // Lower confidence: no MIME detected
    const buf2 = Buffer.alloc(200, 0x41);
    const res2 = engine.analyzeBuffer(buf2, 'unknown.dat');
    expect(res2.confidence).toBeLessThan(100);

    // Lower confidence: suspicious patterns
    const buf3 = Buffer.from('<script>alert(1)</script>');
    const res3 = engine.analyzeBuffer(buf3, 'test.html');
    expect(res3.confidence).toBeLessThan(100);

    // Lower confidence: small buffer
    const buf4 = Buffer.from([0x41]);
    const res4 = engine.analyzeBuffer(buf4, 'small.dat');
    expect(res4.confidence).toBeLessThan(100);
  });

  it('handles logger errors gracefully', () => {
    const faultyLogger = {
      debug: () => {
        throw new Error('Logger error');
      },
      log: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    };
    const engine = new BufferAnalysisEngine({}, faultyLogger);
    const buf = Buffer.from([0xff, 0xd8, 0xff, 0xe0]);

    // Should not throw despite logger error
    expect(() => engine.analyzeBuffer(buf, 'test.jpg')).not.toThrow();
  });

  it('handles analysis errors gracefully', () => {
    const engine = new BufferAnalysisEngine();
    // Mock detectMimeTypeFromBuffer to throw
    const originalDetect = engine['detectMimeTypeFromBuffer'];
    engine['detectMimeTypeFromBuffer'] = () => {
      throw new Error('Detection error');
    };

    const buf = Buffer.from([0xff, 0xd8, 0xff, 0xe0]);
    const result = engine.analyzeBuffer(buf, 'error.jpg');

    expect(result.analysisSkipped).toBe(true);
    expect(result.skipReason).toContain('Analysis failed');

    // Restore
    engine['detectMimeTypeFromBuffer'] = originalDetect;
  });

  it('handles concurrent analysis calls', async () => {
    const engine = new BufferAnalysisEngine();
    const buf = Buffer.from([0xff, 0xd8, 0xff, 0xe0]);

    const promises = Array.from({ length: 10 }, () => engine.analyzeBuffer(buf, 'concurrent.jpg'));

    const results = await Promise.all(promises);
    results.forEach((result) => {
      expect(result.detectedMimeType).toBe('image/jpeg');
    });
  });

  it('handles memory pressure with large analysis depth', () => {
    const engine = new BufferAnalysisEngine({ maxAnalysisDepth: 10 * 1024 * 1024 }); // 10MB
    const largeBuf = Buffer.alloc(5 * 1024 * 1024, 0x41); // 5MB
    const result = engine.analyzeBuffer(largeBuf, 'large.dat');
    expect(result.analysisSkipped).toBe(false);
    // Should analyze only up to maxAnalysisDepth
  });

  it('detects WEBP with wildcard signature', () => {
    const buf = Buffer.from([
      0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50,
    ]);
    const res = engine.analyzeBuffer(buf, 'test.webp');
    expect(res.detectedMimeType).toBe('image/webp');
  });

  it('detects PNG magic bytes', () => {
    const buf = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const result = engine.analyzeBuffer(buf, 'test.png');
    expect(result.detectedMimeType).toBe('image/png');
  });

  it('detects GIF magic bytes', () => {
    const buf = Buffer.from([0x47, 0x49, 0x46, 0x38, 0x39, 0x61]);
    const result = engine.analyzeBuffer(buf, 'test.gif');
    expect(result.detectedMimeType).toBe('image/gif');
  });

  it('detects PDF magic bytes', () => {
    const buf = Buffer.from([0x25, 0x50, 0x44, 0x46]);
    const result = engine.analyzeBuffer(buf, 'test.pdf');
    expect(result.detectedMimeType).toBe('application/pdf');
  });

  it('detects ZIP magic bytes', () => {
    const buf = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
    const result = engine.analyzeBuffer(buf, 'test.zip');
    expect(result.detectedMimeType).toBe('application/zip');
  });

  it('detects MP3 magic bytes', () => {
    const buf = Buffer.from([0xff, 0xfb]);
    const result = engine.analyzeBuffer(buf, 'test.mp3');
    expect(result.detectedMimeType).toBe('audio/mpeg');
  });

  it('detects WAV magic bytes', () => {
    const buf = Buffer.from([
      0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45,
    ]);
    const result = engine.analyzeBuffer(buf, 'test.wav');
    expect(result.detectedMimeType).toBe('audio/wav');
  });

  it('detects HTML magic bytes', () => {
    const buf = Buffer.from([0x3c, 0x68, 0x74, 0x6d, 0x6c]);
    const result = engine.analyzeBuffer(buf, 'test.html');
    expect(result.detectedMimeType).toBe('text/html');
  });

  it('detects XML magic bytes', () => {
    const buf = Buffer.from([0x3c, 0x3f, 0x78, 0x6d, 0x6c]);
    const result = engine.analyzeBuffer(buf, 'test.xml');
    expect(result.detectedMimeType).toBe('application/xml');
  });

  it('detects EXE magic bytes', () => {
    const buf = Buffer.from([0x4d, 0x5a]);
    const result = engine.analyzeBuffer(buf, 'test.exe');
    expect(result.detectedMimeType).toBe('application/x-msdownload');
  });

  it('fails to detect unknown file type', () => {
    const buf = Buffer.from([0x00, 0x01, 0x02, 0x03]);
    const result = engine.analyzeBuffer(buf, 'unknown.dat');
    expect(result.detectedMimeType).toBe(null);
  });

  it('handles empty buffer', () => {
    const buf = Buffer.alloc(0);
    const result = engine.analyzeBuffer(buf, 'empty.dat');
    expect(result.detectedMimeType).toBe(null);
    expect(result.hasSuspiciousPatterns).toBe(false);
    expect(result.analysisSkipped).toBe(false);
    expect(result.confidence).toBeLessThan(100); // Small buffer penalty
  });

  it('handles very large buffer without crashing', () => {
    // Create a large buffer but don't actually allocate it fully to avoid memory issues
    const largeBuf = Buffer.allocUnsafe(100 * 1024 * 1024); // 100MB
    const result = engine.analyzeBuffer(largeBuf, 'large.dat');
    expect(result.analysisSkipped).toBe(true);
    expect(result.skipReason).toContain('File too large');
  });

  it('handles buffer with special characters and unicode', () => {
    const buf = Buffer.from('Hello 🌍 <script>alert("test")</script> 你好', 'utf8');
    const result = engine.analyzeBuffer(buf, 'unicode.txt');
    expect(result.hasSuspiciousPatterns).toBe(true);
    expect(result.suspiciousPatterns).toContain('HTML Script Tag');
  });

  it('handles invalid buffer input gracefully', () => {
    // @ts-expect-error Testing invalid input
    const result = engine.analyzeBuffer('not a buffer', 'invalid.dat');
    expect(result.analysisSkipped).toBe(true);
    expect(result.skipReason).toContain('Invalid input');
  });

  it('handles null/undefined filename', () => {
    const buf = Buffer.from([0xff, 0xd8, 0xff, 0xe0]);
    expect(() => engine.analyzeBuffer(buf)).not.toThrow();
    expect(() => engine.analyzeBuffer(buf, undefined)).not.toThrow();
  });

  it('magic-bytes helpers', () => {
    expect(getSupportedMimeTypes()).toContain('image/png');
    expect(hasMagicBytesSignature('image/png')).toBe(true);
    expect(getSignaturesForMimeType('image/png').length).toBeGreaterThan(0);
  });

  it('can add and remove magic-byte signatures dynamically', () => {
    const testSig = [0x01, 0x02, 0x03];
    addMagicBytesSignature('application/x-test', testSig);
    expect(hasMagicBytesSignature('application/x-test')).toBe(true);
    expect(getSignaturesForMimeType('application/x-test')[0]).toEqual(testSig);
    removeMagicBytesSignatures('application/x-test');
    expect(hasMagicBytesSignature('application/x-test')).toBe(false);
  });

  it('getSignaturesForMimeType returns empty array for unknown MIME type', () => {
    expect(getSignaturesForMimeType('unknown/type')).toEqual([]);
  });

  it('hasMagicBytesSignature returns false for unknown MIME type', () => {
    expect(hasMagicBytesSignature('unknown/type')).toBe(false);
  });

  it('addMagicBytesSignature handles multiple signatures for same MIME type', () => {
    const sig1 = [0x01, 0x02];
    const sig2 = [0x03, 0x04];
    addMagicBytesSignature('application/x-multi', sig1);
    addMagicBytesSignature('application/x-multi', sig2);
    const sigs = getSignaturesForMimeType('application/x-multi');
    expect(sigs).toContain(sig1);
    expect(sigs).toContain(sig2);
    removeMagicBytesSignatures('application/x-multi');
  });

  it('addMagicBytesSignature handles empty signature', () => {
    addMagicBytesSignature('application/x-empty', []);
    const sigs = getSignaturesForMimeType('application/x-empty');
    expect(sigs).toEqual([[]]);
    removeMagicBytesSignatures('application/x-empty');
  });

  it('addMagicBytesSignature handles null values in signature', () => {
    const sig = [0x01, null, 0x03];
    addMagicBytesSignature('application/x-null', sig);
    const sigs = getSignaturesForMimeType('application/x-null');
    expect(sigs).toEqual([sig]);
    removeMagicBytesSignatures('application/x-null');
  });

  it('removeMagicBytesSignatures handles non-existent MIME type', () => {
    expect(() => removeMagicBytesSignatures('non-existent/type')).not.toThrow();
  });

  it('analyzeStream works on small readable streams', async () => {
    const { Readable } = await import('stream');
    const r = Readable.from([Buffer.from([0xff, 0xd8, 0xff, 0xe0])]);
    const res = await engine.analyzeStream(r, 'stream.jpg');
    expect(res.detectedMimeType).toBe('image/jpeg');
  });

  it('analyzeStream convenience export works', async () => {
    const { Readable } = await import('stream');
    const r = Readable.from([Buffer.from([0xff, 0xd8, 0xff, 0xe0])]);
    const res = await analyzeStream(r, 'stream.jpg');
    expect(res.detectedMimeType).toBe('image/jpeg');
  });

  it('analyzeStream skips large streams when configured', async () => {
    const { Readable } = await import('stream');
    const engine = new BufferAnalysisEngine({ maxFileSize: 10, skipLargeFiles: true });
    const largeChunks = Array.from({ length: 20 }, () => Buffer.alloc(10, 0x41));
    const r = Readable.from(largeChunks);
    const res = await engine.analyzeStream(r, 'large.dat');
    expect(res.analysisSkipped).toBe(true);
    expect(res.skipReason).toContain('File too large');
  });

  it('analyzeStream respects per-call config', async () => {
    const { Readable } = await import('stream');
    const r = Readable.from([Buffer.from([0xff, 0xd8, 0xff, 0xe0])]);
    const res = await analyzeStream(r, 'stream.jpg', { enableMagicBytesDetection: false });
    expect(res.detectedMimeType).toBe(null);
  });

  it('analyzeStream handles empty stream', async () => {
    const { Readable } = await import('stream');
    const r = Readable.from([]);
    const res = await engine.analyzeStream(r, 'empty.dat');
    expect(res.detectedMimeType).toBe(null);
    expect(res.analysisSkipped).toBe(false);
  });

  it('analyzeStream detects suspicious patterns in stream', async () => {
    const { Readable } = await import('stream');
    const chunks = [
      Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
      Buffer.from('<script>alert(1)</script>'),
    ];
    const r = Readable.from(chunks);
    const res = await engine.analyzeStream(r, 'stream.jpg');
    expect(res.hasSuspiciousPatterns).toBe(true);
  });

  it('analyzeStream handles invalid readable input', async () => {
    // @ts-expect-error Testing invalid input
    const res = await engine.analyzeStream(null, 'invalid.dat');
    expect(res.analysisSkipped).toBe(true);
    expect(res.skipReason).toContain('Invalid input');
  });

  it('analyzeStream handles stream with mixed data types', async () => {
    const { Readable } = await import('stream');
    const chunks = [
      Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
      'DROP TABLE users', // This should be converted to Buffer and detected
    ];
    const r = Readable.from(chunks);
    const res = await engine.analyzeStream(r, 'mixed.dat');
    expect(res.detectedMimeType).toBe('image/jpeg');
    expect(res.hasSuspiciousPatterns).toBe(true);
    expect(res.suspiciousPatterns).toContain('SQL Drop Command');
  });

  it('analyzeStream handles stream error gracefully', async () => {
    const { Readable } = await import('stream');
    const r = new Readable({
      read() {
        this.emit('error', new Error('Stream error'));
      },
    });
    const res = await engine.analyzeStream(r, 'error.dat');
    expect(res.analysisSkipped).toBe(true);
    expect(res.skipReason).toContain('Stream read error');
  });

  it('express middleware attaches analysis when body is a buffer', async () => {
    const middleware = expressBufferAnalysisMiddleware({ attachProperty: 'ba' });
    const req: any = { body: Buffer.from([0xff, 0xd8, 0xff, 0xe0]) };
    let called = false;
    const next = () => {
      called = true;
    };
    await middleware(req, {}, next);
    expect(called).toBe(true);
    expect(req.ba).toBeTruthy();
    expect(req.ba.detectedMimeType).toBe('image/jpeg');
  });

  it('express middleware attaches analysis when body is a string', async () => {
    const middleware = expressBufferAnalysisMiddleware({ attachProperty: 'analysis' });
    const req: any = { body: '<html>test</html>' };
    let called = false;
    const next = () => {
      called = true;
    };
    await middleware(req, {}, next);
    expect(called).toBe(true);
    expect(req.analysis).toBeTruthy();
    expect(req.analysis.detectedMimeType).toBe('text/html');
  });

  it('express middleware uses custom attach property', async () => {
    const middleware = expressBufferAnalysisMiddleware({ attachProperty: 'customProp' });
    const req: any = { body: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) };
    let called = false;
    const next = () => {
      called = true;
    };
    await middleware(req, {}, next);
    expect(called).toBe(true);
    expect(req.customProp).toBeTruthy();
    expect(req.customProp.detectedMimeType).toBe('image/png');
  });

  it('express middleware uses filename field', async () => {
    const middleware = expressBufferAnalysisMiddleware({ filenameField: 'fileName' });
    const req: any = { body: Buffer.from([0xff, 0xd8, 0xff, 0xe0]), fileName: 'test.jpg' };
    let called = false;
    const next = () => {
      called = true;
    };
    await middleware(req, {}, next);
    expect(called).toBe(true);
    expect(req.bufferAnalysis).toBeTruthy();
  });

  it('express middleware respects config options', async () => {
    const middleware = expressBufferAnalysisMiddleware({
      config: { enableMagicBytesDetection: false },
      attachProperty: 'ba',
    });
    const req: any = { body: Buffer.from([0xff, 0xd8, 0xff, 0xe0]) };
    let called = false;
    const next = () => {
      called = true;
    };
    await middleware(req, {}, next);
    expect(called).toBe(true);
    expect(req.ba.detectedMimeType).toBe(null);
  });

  it('koa middleware attaches analysis when body is a buffer', async () => {
    const middleware = koaBufferAnalysisMiddleware({ attachProperty: 'ba' });
    const ctx: any = { request: { body: Buffer.from([0xff, 0xd8, 0xff, 0xe0]) } };
    let called = false;
    const next = async () => {
      called = true;
    };
    await middleware(ctx, next);
    expect(called).toBe(true);
    expect(ctx.ba).toBeTruthy();
    expect(ctx.ba.detectedMimeType).toBe('image/jpeg');
  });

  it('koa middleware attaches analysis when body is a string', async () => {
    const middleware = koaBufferAnalysisMiddleware({ attachProperty: 'analysis' });
    const ctx: any = { request: { body: '<html>test</html>' } };
    let called = false;
    const next = async () => {
      called = true;
    };
    await middleware(ctx, next);
    expect(called).toBe(true);
    expect(ctx.analysis).toBeTruthy();
    expect(ctx.analysis.detectedMimeType).toBe('text/html');
  });

  it('express middleware handles missing body', async () => {
    const middleware = expressBufferAnalysisMiddleware();
    const req: any = {};
    let called = false;
    const next = () => {
      called = true;
    };
    await middleware(req, {}, next);
    expect(called).toBe(true);
    expect(req.bufferAnalysis).toBeUndefined();
  });

  it('express middleware handles non-string non-buffer body', async () => {
    const middleware = expressBufferAnalysisMiddleware();
    const req: any = { body: { key: 'value' } };
    let called = false;
    const next = () => {
      called = true;
    };
    await middleware(req, {}, next);
    expect(called).toBe(true);
    expect(req.bufferAnalysis).toBeUndefined();
  });

  it('koa middleware handles missing body', async () => {
    const middleware = koaBufferAnalysisMiddleware();
    const ctx: any = { request: {} };
    let called = false;
    const next = async () => {
      called = true;
    };
    await middleware(ctx, next);
    expect(called).toBe(true);
    expect(ctx.bufferAnalysis).toBeUndefined();
  });

  it('express middleware handles errors gracefully', async () => {
    // Create middleware with invalid config to force error
    const middleware = expressBufferAnalysisMiddleware({ config: { maxAnalysisDepth: -1 } });
    const req: any = { body: Buffer.from([0xff, 0xd8, 0xff, 0xe0]) };
    let error: any = null;
    const next = (err?: any) => {
      error = err;
    };

    await middleware(req, {}, next);
    expect(error).toBeInstanceOf(Error);
  });
});

describe('Suspicious Patterns Module', () => {
  it('should have non-empty suspicious patterns array', () => {
    expect(SUSPICIOUS_PATTERNS).toBeDefined();
    expect(Array.isArray(SUSPICIOUS_PATTERNS)).toBe(true);
    expect(SUSPICIOUS_PATTERNS.length).toBeGreaterThan(0);
  });

  it('should have valid pattern structure', () => {
    for (const pattern of SUSPICIOUS_PATTERNS) {
      expect(pattern).toHaveProperty('pattern');
      expect(pattern).toHaveProperty('name');
      expect(Buffer.isBuffer(pattern.pattern)).toBe(true);
      expect(typeof pattern.name).toBe('string');
      expect(pattern.name.length).toBeGreaterThan(0);
    }
  });

  it('should detect suspicious patterns correctly', () => {
    const testBuffer = Buffer.from('<script>alert(1)</script>');
    const result = analyzeSuspiciousPatterns(testBuffer);
    expect(result.hasSuspicious).toBe(true);
    expect(result.patterns).toContain('HTML Script Tag');
    expect(result.patterns).toContain('HTML Script Close Tag');
  });

  it('should return empty result for clean buffer', () => {
    const cleanBuffer = Buffer.from('Hello World');
    const result = analyzeSuspiciousPatterns(cleanBuffer);
    expect(result.hasSuspicious).toBe(false);
    expect(result.patterns).toEqual([]);
  });

  it('should respect maxAnalysisDepth parameter', () => {
    const buffer = Buffer.concat([
      Buffer.alloc(50, 0x41), // Fill first 50 bytes
      Buffer.from('<script>alert(1)</script>'), // Add pattern after
    ]);
    const result = analyzeSuspiciousPatterns(buffer, 40); // Only analyze first 40 bytes
    expect(result.hasSuspicious).toBe(false); // Should not find pattern beyond depth
  });

  it('should get all suspicious pattern names', () => {
    const names = getAllSuspiciousPatternNames();
    expect(Array.isArray(names)).toBe(true);
    expect(names.length).toBe(SUSPICIOUS_PATTERNS.length);
    expect(names).toContain('HTML Script Tag');
    expect(names).toContain('SQL Drop Command');
  });

  it('should get suspicious pattern count', () => {
    const count = getSuspiciousPatternCount();
    expect(typeof count).toBe('number');
    expect(count).toBe(SUSPICIOUS_PATTERNS.length);
    expect(count).toBeGreaterThan(50); // Should have many patterns
  });

  it('should filter patterns by category', () => {
    const htmlPatterns = getPatternsByCategory('HTML');
    expect(Array.isArray(htmlPatterns)).toBe(true);
    expect(htmlPatterns.length).toBeGreaterThan(0);

    // Check that all returned patterns start with 'HTML'
    for (const pattern of htmlPatterns) {
      expect(pattern.name.startsWith('HTML')).toBe(true);
    }

    const sqlPatterns = getPatternsByCategory('SQL');
    expect(Array.isArray(sqlPatterns)).toBe(true);
    expect(sqlPatterns.length).toBeGreaterThan(0);

    // Check that all returned patterns start with 'SQL'
    for (const pattern of sqlPatterns) {
      expect(pattern.name.startsWith('SQL')).toBe(true);
    }
  });

  it('should handle case-insensitive category filtering', () => {
    const htmlPatterns1 = getPatternsByCategory('html');
    const htmlPatterns2 = getPatternsByCategory('HTML');
    expect(htmlPatterns1.length).toBe(htmlPatterns2.length);
  });

  it('should return empty array for non-existent category', () => {
    const nonExistent = getPatternsByCategory('NonExistentCategory');
    expect(nonExistent).toEqual([]);
  });

  it('should detect multiple pattern types simultaneously', () => {
    const buffer = Buffer.from(`
      <script>alert('xss')</script>
      DROP TABLE users;
      eval('code');
      /etc/passwd
    `);

    const result = analyzeSuspiciousPatterns(buffer);
    expect(result.hasSuspicious).toBe(true);
    expect(result.patterns.length).toBeGreaterThan(3);
    expect(result.patterns).toContain('HTML Script Tag');
    expect(result.patterns).toContain('SQL Drop Command');
    expect(result.patterns).toContain('JavaScript Eval');
    expect(result.patterns).toContain('Unix Passwd File');
  });

  it('should handle empty buffer', () => {
    const result = analyzeSuspiciousPatterns(Buffer.alloc(0));
    expect(result.hasSuspicious).toBe(false);
    expect(result.patterns).toEqual([]);
  });

  it('should handle binary data', () => {
    const binaryBuffer = Buffer.from([
      0x00, 0x01, 0x02, 0x3c, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x3e,
    ]); // Contains '<script>'
    const result = analyzeSuspiciousPatterns(binaryBuffer);
    expect(result.hasSuspicious).toBe(true);
    expect(result.patterns).toContain('HTML Script Tag');
  });
});
