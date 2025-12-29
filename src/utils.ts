export function safeObjectAssign<T extends Record<string, unknown>>(target: T, source: Record<string, unknown>, allowedKeys: string[]): T {
  for (const key of allowedKeys) {
    if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
    if (key === "__proto__" || key === "constructor" || key === "prototype") continue;
    const value = source[key];
    if (value !== undefined) {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      (target as Record<string, unknown>)[key] = value;
    }
  }
  return target;
}

export interface SimpleLogger {
  debug?: (...args: unknown[]) => void;
  log?: (...args: unknown[]) => void;
  warn?: (...args: unknown[]) => void;
  error?: (...args: unknown[]) => void;
}

export const consoleLikeLogger: SimpleLogger = {
  debug: (...args: unknown[]) => {
    if (typeof console !== "undefined" && console.debug) console.debug(...args);
  },
  log: (...args: unknown[]) => {
    if (typeof console !== "undefined" && console.log) console.log(...args);
  },
  warn: (...args: unknown[]) => {
    if (typeof console !== "undefined" && console.warn) console.warn(...args);
  },
  error: (...args: unknown[]) => {
    if (typeof console !== "undefined" && console.error) console.error(...args);
  },
};
