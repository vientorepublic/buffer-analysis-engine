import type { BufferAnalysisResult } from '../types';

declare module 'koa' {
  interface DefaultContext {
    bufferAnalysis?: BufferAnalysisResult;
    rawBody?: Buffer;
  }
}
