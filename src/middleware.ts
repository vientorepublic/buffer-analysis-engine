import type { ReadableLike } from './types';
import { analyzeBuffer, analyzeStream } from './engine';
import type { BufferAnalysisConfig } from './types';
import { Readable } from 'stream';

export interface MiddlewareOptions {
  /** If true, middleware will consume request stream when no parsed body is present (body will be buffered up to maxAnalysisDepth) */
  consumeRequestStream?: boolean;
  /** Field name to attach analysis result on the request/context */
  attachProperty?: string;
  /** Optional filename provider */
  filenameField?: string;
  config?: BufferAnalysisConfig;
}

export function expressBufferAnalysisMiddleware(opts: MiddlewareOptions = {}) {
  const attach = opts.attachProperty ?? 'bufferAnalysis';

  return async (req: any, res: any, next: any) => {
    try {
      // If body is buffer or string (already parsed), use it
      if (req.body && Buffer.isBuffer(req.body)) {
        const result = analyzeBuffer(
          req.body,
          opts.filenameField ? req[opts.filenameField] : undefined,
          opts.config,
        );
        req[attach] = result;
        return next();
      }

      if (req.body && typeof req.body === 'string') {
        const buf = Buffer.from(req.body);
        const result = analyzeBuffer(
          buf,
          opts.filenameField ? req[opts.filenameField] : undefined,
          opts.config,
        );
        req[attach] = result;
        return next();
      }

      if (opts.consumeRequestStream && req.readable) {
        // Buffer up to maxAnalysisDepth, then attach
        const resu = await analyzeStream(
          req as ReadableLike,
          opts.filenameField ? req[opts.filenameField] : undefined,
          opts.config ?? undefined,
        );
        req[attach] = resu;
        // Also capture raw buffer for downstream handlers if they want it
        // Note: this consumes the request stream.
        // Best practice: use after body parsers or ensure downstream reads from req.rawBody
        req.rawBody = Buffer.isBuffer(req._raw) ? req._raw : undefined;
        return next();
      }

      return next();
    } catch (err) {
      return next(err);
    }
  };
}

export function koaBufferAnalysisMiddleware(opts: MiddlewareOptions = {}) {
  const attach = opts.attachProperty ?? 'bufferAnalysis';

  return async (ctx: any, next: any) => {
    if (ctx.request && ctx.request.body && Buffer.isBuffer(ctx.request.body)) {
      ctx[attach] = analyzeBuffer(
        ctx.request.body,
        opts.filenameField ? ctx.request[opts.filenameField] : undefined,
        opts.config,
      );
    } else if (opts.consumeRequestStream) {
      // Koa body may be a stream
      const reqStream = ctx.req as Readable;
      if (reqStream) {
        ctx[attach] = await analyzeStream(
          reqStream,
          opts.filenameField ? ctx.request[opts.filenameField] : undefined,
          opts.config,
        );
      }
    }
    await next();
  };
}
