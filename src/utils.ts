/**
 * Safely assigns properties from source to target, protecting against prototype pollution.
 * Only assigns allowed keys and skips dangerous property names.
 * @param target - Target object to assign properties to
 * @param source - Source object to copy properties from
 * @param allowedKeys - List of allowed property keys
 * @returns Target object with assigned properties
 */
export function safeObjectAssign<T extends Record<string, unknown>>(
  target: T,
  source: Record<string, unknown>,
  allowedKeys: string[],
): T {
  for (const key of allowedKeys) {
    if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    const value = source[key];
    if (value !== undefined) {
      (target as Record<string, unknown>)[key] = value;
    }
  }
  return target;
}

/**
 * Simple logger interface for diagnostic messages.
 * All methods are optional to support partial implementations.
 */
export interface SimpleLogger {
  debug?: (...args: unknown[]) => void;
  log?: (...args: unknown[]) => void;
  warn?: (...args: unknown[]) => void;
  error?: (...args: unknown[]) => void;
}

/**
 * Console-based logger implementation.
 * Safely wraps console methods to handle environments where console may not be available.
 */
export const consoleLikeLogger: SimpleLogger = {
  debug: (...args: unknown[]) => {
    if (typeof console !== 'undefined' && console.debug) console.debug(...args);
  },
  log: (...args: unknown[]) => {
    if (typeof console !== 'undefined' && console.log) console.log(...args);
  },
  warn: (...args: unknown[]) => {
    if (typeof console !== 'undefined' && console.warn) console.warn(...args);
  },
  error: (...args: unknown[]) => {
    if (typeof console !== 'undefined' && console.error) console.error(...args);
  },
};
/**
 * Silent logger implementation that discards all log messages.
 * Useful as a default logger to avoid noisy output.
 */
export const silentLogger: SimpleLogger = {
  debug: () => {},
  log: () => {},
  warn: () => {},
  error: () => {},
};
