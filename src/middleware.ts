import type { ReadableLike } from './types';
import { analyzeBuffer, analyzeStream } from './engine';
import type { BufferAnalysisConfig } from './types';
import type { Request, Response, NextFunction } from 'express';
import type { Context, Next as KoaNext } from 'koa';
import { Readable } from 'stream';

/**
 * Configuration options for buffer analysis middleware.
 */
export interface MiddlewareOptions {
  /** If true, middleware will consume request stream when no parsed body is present (body will be buffered up to maxAnalysisDepth) */
  consumeRequestStream?: boolean;
  /** Field name to attach analysis result on the request/context */
  attachProperty?: string;
  /** Optional filename provider */
  filenameField?: string;
  config?: BufferAnalysisConfig;
}

/**
 * Creates Express middleware for buffer analysis.
 * Analyzes request body if it's a Buffer or string, or optionally consumes request stream.
 * Attaches analysis result to the request object.
 * @param opts - Middleware configuration options
 * @returns Express middleware function
 * @example
 * ```typescript
 * app.use(expressBufferAnalysisMiddleware({
 *   attachProperty: 'fileAnalysis',
 *   consumeRequestStream: false
 * }));
 * ```
 */
export function expressBufferAnalysisMiddleware(opts: MiddlewareOptions = {}) {
  const attach = opts.attachProperty ?? 'bufferAnalysis';

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const filename = opts.filenameField
        ? ((req as any)[opts.filenameField] as string | undefined)
        : undefined;

      // If body is buffer (already parsed), use it
      if (req.body && Buffer.isBuffer(req.body)) {
        const result = analyzeBuffer(req.body, filename, opts.config);
        (req as any)[attach] = result;
        return next();
      }

      // If body is a parsed string
      if (req.body && typeof req.body === 'string') {
        const buf = Buffer.from(req.body);
        (req as any)[attach] = analyzeBuffer(buf, filename, opts.config);
        return next();
      }

      // Optionally consume the raw request stream (beware: this will consume the stream)
      const readableReq = req as unknown as NodeJS.ReadableStream;
      if (opts.consumeRequestStream && (readableReq as any).readable) {
        const resu = await analyzeStream(
          readableReq as ReadableLike,
          filename,
          opts.config ?? undefined,
        );
        (req as any)[attach] = resu;
        (req as any).rawBody = Buffer.isBuffer((req as any)._raw) ? (req as any)._raw : undefined;
        return next();
      }

      return next();
    } catch (err) {
      return next(err as Error);
    }
  };
}

/**
 * Creates Koa middleware for buffer analysis.
 * Analyzes request body if it's a Buffer or string, or optionally consumes request stream.
 * Attaches analysis result to the context object.
 * @param opts - Middleware configuration options
 * @returns Koa middleware function
 * @example
 * ```typescript
 * app.use(koaBufferAnalysisMiddleware({
 *   attachProperty: 'fileAnalysis',
 *   consumeRequestStream: false
 * }));
 * ```
 */
export function koaBufferAnalysisMiddleware(opts: MiddlewareOptions = {}) {
  const attach = opts.attachProperty ?? 'bufferAnalysis';

  return async (ctx: Context, next: KoaNext) => {
    const filename = opts.filenameField
      ? ((ctx.request as any)[opts.filenameField] as string | undefined)
      : undefined;

    const koaBody = (ctx.request as any).body;
    if (koaBody && Buffer.isBuffer(koaBody)) {
      (ctx as any)[attach] = analyzeBuffer(koaBody, filename, opts.config);
    } else if (koaBody && typeof koaBody === 'string') {
      (ctx as any)[attach] = analyzeBuffer(Buffer.from(koaBody), filename, opts.config);
    } else if (opts.consumeRequestStream) {
      const reqStream = ctx.req as Readable;
      if (reqStream) {
        (ctx as any)[attach] = await analyzeStream(reqStream, filename, opts.config);
      }
    }

    await next();
  };
}
