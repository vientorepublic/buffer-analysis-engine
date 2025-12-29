# Changelog

## 0.1.2 - 2025-12-29

- Add: `analyzeStream` to support stream-based analysis (Readables / async-iterables).
- Add: dynamic signature management (`addMagicBytesSignature`, `removeMagicBytesSignatures`, `getMaxSignatureLength`).
- Add: Express and Koa middleware factories for easy integration.
- Tests: added stream/middleware/signature tests.
- Docs: README expanded with Streaming and Integration sections.

## 0.1.1 - 2025-12-29

- Fix: `analyzeBuffer` now respects per-call `config` by using a temporary engine when provided.
- Add: `resetBufferAnalysisEngine()` to reset the global singleton (useful in tests/reconfiguration).
- Fix: improved magic-bytes matching implementation for clarity and reliability.
- Test: added unit tests for WEBP/MP4/wildcard signatures and new helpers.
- Docs: expanded README with API and usage examples.
- CI: added GitHub Actions workflow to run build & tests.
