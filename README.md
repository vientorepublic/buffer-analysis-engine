# Buffer Analysis Engine

[![License](https://img.shields.io/badge/License-MIT-blue)](#license)
[![stars - buffer-analysis-engine](https://img.shields.io/github/stars/vientorepublic/buffer-analysis-engine?style=social)](https://github.com/vientorepublic/buffer-analysis-engine)
[![forks - buffer-analysis-engine](https://img.shields.io/github/forks/vientorepublic/buffer-analysis-engine?style=social)](https://github.com/vientorepublic/buffer-analysis-engine)
[![npm version](https://badge.fury.io/js/buffer-analysis-engine.svg)](https://badge.fury.io/js/buffer-analysis-engine)

Lightweight, dependency-free buffer analysis engine for detecting MIME types (magic bytes) and quick heuristic suspicious-patterns in buffers.

---

## Features

- Fast magic-bytes based MIME type detection
- Heuristic suspicious pattern scanning (HTML/JS/SQL/shell snippets)
- Configurable analysis depth and file-size skipping
- Minimal, dependency-free TypeScript implementation

---

## Installation

```bash
npm install buffer-analysis-engine --save
# or
pnpm add buffer-analysis-engine
```

---

## Quick Start

```ts
import {
  BufferAnalysisEngine,
  analyzeBuffer,
  getBufferAnalysisEngine,
  resetBufferAnalysisEngine,
  MAGIC_BYTES_SIGNATURES,
  analyzeSuspiciousPatterns,
  getPatternsByCategory,
} from 'buffer-analysis-engine';

const engine = new BufferAnalysisEngine();
const buf = Buffer.from([0xff, 0xd8, 0xff, 0xe0]);

// instance API
const result = engine.analyzeBuffer(buf, 'photo.jpg');
console.log(result.detectedMimeType); // "image/jpeg"

// convenience: per-call config uses a temporary engine and thus respects the supplied options
const oneOff = analyzeBuffer(buf, 'photo.jpg', { enableMagicBytesDetection: true });

// direct suspicious pattern analysis
const maliciousBuf = Buffer.from('<script>alert(1)</script>');
const patternResult = analyzeSuspiciousPatterns(maliciousBuf);
console.log(patternResult.hasSuspicious); // true
console.log(patternResult.patterns); // ['HTML Script Tag', 'HTML Script Close Tag']

// get patterns by category
const sqlPatterns = getPatternsByCategory('SQL');
console.log(sqlPatterns.length); // number of SQL-related patterns

// reset the global instance (useful in tests or to reconfigure)
resetBufferAnalysisEngine();

// inspect available signatures
console.log(Object.keys(MAGIC_BYTES_SIGNATURES));
```

> Note: `getBufferAnalysisEngine()` returns a global singleton. If you pass a `config` to `getBufferAnalysisEngine()` it only affects the first initialization. To recreate the global instance, call `resetBufferAnalysisEngine()`.

---

## API Reference

- BufferAnalysisEngine
  - constructor(config?: BufferAnalysisConfig, logger?: SimpleLogger)
  - analyzeBuffer(buffer: Buffer, filename?: string): BufferAnalysisResult
  - getConfig(), updateConfig(), enable(), disable(), isEnabled()

- analyzeBuffer(buffer, filename?, config?) — convenience function. If `config` is provided it creates a temporary engine for that call (won't mutate global singleton).

- getBufferAnalysisEngine(config?, logger?) — returns a global singleton instance (first call initializes it with given config).

- resetBufferAnalysisEngine() — reset the global singleton (useful in tests or when reconfiguring at runtime).

- MAGIC_BYTES_SIGNATURES — exported map of mime types -> magic byte signatures
- addMagicBytesSignature(mimeType, signature) — add a magic signature at runtime
- removeMagicBytesSignatures(mimeType) — remove all signatures for a mime type

- SUSPICIOUS_PATTERNS — exported array of suspicious pattern definitions
- analyzeSuspiciousPatterns(buffer, maxAnalysisDepth?) — analyze buffer for security threats
- getAllSuspiciousPatternNames() — get all pattern names
- getSuspiciousPatternCount() — get total number of patterns
- getPatternsByCategory(category) — filter patterns by category (e.g., 'HTML', 'SQL')

- analyzeStream(readable, filename?, config?) — analyze a Readable or async iterable stream (returns a Promise<BufferAnalysisResult>)
- expressBufferAnalysisMiddleware(opts) / koaBufferAnalysisMiddleware(opts) — middleware factories for Express and Koa to attach analysis results to requests

---

## Suspicious Pattern Analysis

The engine includes a comprehensive set of patterns to detect various security threats including XSS, SQL injection, command injection, and other malicious content.

### Direct Pattern Analysis

```ts
import { analyzeSuspiciousPatterns, getPatternsByCategory } from 'buffer-analysis-engine';

// Analyze a buffer for suspicious patterns with context
const buffer = Buffer.from('<script>alert("XSS")</script> DROP TABLE users');
const mimeType = 'text/html'; // Optional: filters inapplicable patterns
const maxDepth = 1024;
const threshold = 1;

const result = analyzeSuspiciousPatterns(buffer, mimeType, maxDepth, threshold);

console.log(result.hasSuspicious); // true
console.log(result.patterns); // ['HTML Script Tag', 'SQL Drop Command', ...]
console.log(result.score); // Total risk score (e.g., 5)

// Get patterns by category
const htmlPatterns = getPatternsByCategory('HTML');
const sqlPatterns = getPatternsByCategory('SQL');
const jsPatterns = getPatternsByCategory('JavaScript');

// Get all pattern names
import { getAllSuspiciousPatternNames } from 'buffer-analysis-engine';
const allNames = getAllSuspiciousPatternNames();
console.log(`Total patterns: ${allNames.length}`);
```

### Pattern Categories

The suspicious patterns are organized into categories:

- **HTML/XSS**: Script tags, event handlers, iframe/object/embed tags
- **JavaScript**: Eval, alert, confirm, Function constructor, localStorage access
- **SQL Injection**: DROP/TRUNCATE/UNION/SELECT statements, comments, tautologies
- **Command Injection**: Exec, system, shell commands, command operators
- **PHP**: Include/require, eval, create_function
- **Python**: Exec, eval, subprocess, import calls
- **File System**: Path traversal, passwd/shadow files
- **Encoding**: Base64, URL encoding functions

### Custom Pattern Analysis

```ts
// Only analyze first 1KB of a large buffer, with threshold 3
const result = analyzeSuspiciousPatterns(largeBuffer, 'text/plain', 1024, 3);
```

---

## Stream Analysis

You can analyze Readable streams (or async iterables of Buffer chunks) without buffering the entire file into memory. The convenience function `analyzeStream(readable, filename?, config?)` returns a promise resolving to `BufferAnalysisResult`.

Example:

```ts
import { analyzeStream } from 'buffer-analysis-engine';
import { Readable } from 'stream';

const r = Readable.from([Buffer.from([0xff, 0xd8, 0xff, 0xe0])]);
const res = await analyzeStream(r, 'photo.jpg');
```

Notes:

- For suspicious-pattern analysis, the implementation buffers up to `maxAnalysisDepth` bytes (default 1 MiB).
- For magic-bytes detection, the stream reader continues reading until the required buffer depth is met, ensuring accurate detection even for patterns deeper in the file (if configured).

---

## Integration (Express / Koa)

We provide tiny middleware factories to help integrate the engine into Node.js web services.

Example (Express):

```ts
import express from 'express';
import { expressBufferAnalysisMiddleware } from 'buffer-analysis-engine';

const app = express();
// Use after body parsers so body is available as Buffer/string
app.use(expressBufferAnalysisMiddleware({ attachProperty: 'bufferAnalysis' }));

app.post('/upload', (req, res) => {
  // req.bufferAnalysis is attached by middleware
  res.json({ mime: req.bufferAnalysis?.detectedMimeType });
});
```

If you need middleware to inspect raw streams (before body parsing) you can enable `consumeRequestStream: true` but beware this consumes the request body; downstream handlers must read from `req.rawBody` if you attach it.

---

## Signature management

You can add and remove signatures at runtime:

```ts
import { addMagicBytesSignature, removeMagicBytesSignatures } from 'buffer-analysis-engine';
addMagicBytesSignature('application/x-custom', [0x01, 0x02, 0x03]);
```

---

## Configuration Options

| Option                          |    Type | Default | Description                                          |
| ------------------------------- | ------: | ------- | ---------------------------------------------------- |
| enableMagicBytesDetection       | boolean | true    | Toggle magic-bytes/MIME detection                    |
| enableSuspiciousPatternAnalysis | boolean | true    | Toggle suspicious pattern scanning                   |
| maxAnalysisDepth                |  number | 1 MiB   | Max bytes to scan for patterns                       |
| skipLargeFiles                  | boolean | true    | If true, files larger than `maxFileSize` are skipped |
| maxFileSize                     |  number | 50 MiB  | Threshold for skipping large files                   |
| suspiciousThreshold             |  number | 1       | Minimum score to flag as suspicious                  |
| mimeTypeSpecificConfig          |  object | {}      | Per-MIME type configuration overrides                |

### Advanced Configuration

The engine supports granular configuration for different file types and security requirements.

**Suspicious Thresholds**:
Patterns have assigned weights (e.g., `alert()` = 1, `DROP TABLE` = 3). Content is flagged only if the total score meets or exceeds `suspiciousThreshold`.

**MIME-Type Overrides**:
You can apply stricter or looser rules for specific file types using `mimeTypeSpecificConfig`:

```ts
const engine = new BufferAnalysisEngine({
  suspiciousThreshold: 1, // Default strict
  mimeTypeSpecificConfig: {
    'text/javascript': {
      suspiciousThreshold: 5, // Allow some patterns in JS files
      maxAnalysisDepth: 5 * 1024 * 1024, // Scan deeper in JS
    },
  },
});
```

---

## Tests & Development

- Run tests: `npm test`
- Build: `npm run build`

We use Vitest for unit tests and TypeScript for static types.

---

## Contributing

Contributions are welcome — please open issues or PRs with clear descriptions and tests.

---

## License

MIT
