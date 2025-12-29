import type { BufferAnalysisResult } from '../types';

declare global {
  namespace Express {
    interface Request {
      /** Optional analysis result attached by middleware */
      bufferAnalysis?: BufferAnalysisResult;
      /** Raw buffered body if middleware consumed the request stream */
      rawBody?: Buffer;
    }
  }
}
