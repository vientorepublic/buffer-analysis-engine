# Buffer Analysis Engine

A lightweight, dependency-free buffer analysis engine for detecting MIME types and suspicious patterns in buffers.

Usage:

```ts
import { BufferAnalysisEngine, analyzeBuffer } from "buffer-analysis-engine";

const engine = new BufferAnalysisEngine();
const result = engine.analyzeBuffer(buffer, "file.jpg");
```

API:

- BufferAnalysisEngine
- analyzeBuffer
- getBufferAnalysisEngine
- logBufferAnalysisStatus
- MAGIC_BYTES_SIGNATURES

License: MIT
