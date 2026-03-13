/**
 * Suspicious pattern definitions and analysis functions for buffer security analysis.
 * This module contains patterns for detecting various security threats including XSS,
 * SQL injection, command injection, and other malicious content.
 */

import { SuspiciousPattern } from './types';

/**
 * Collection of suspicious patterns organized by category.
 * Each pattern represents a potential security threat that should be flagged during buffer analysis.
 */
export const SUSPICIOUS_PATTERNS: SuspiciousPattern[] = [
  {
    pattern: Buffer.from('<script', 'utf8'),
    name: 'HTML Script Tag',
    applicableMimeTypes: ['text/html'],
    weight: 2,
  },
  {
    pattern: Buffer.from('javascript:', 'utf8'),
    name: 'JavaScript Protocol',
    applicableMimeTypes: ['text/html', 'text/plain'],
    weight: 3,
  },
  {
    pattern: Buffer.from('vbscript:', 'utf8'),
    name: 'VBScript Protocol',
    applicableMimeTypes: ['text/html', 'text/plain'],
    weight: 3,
  },
  {
    pattern: Buffer.from('/JavaScript', 'utf8'),
    name: 'PDF JavaScript',
    applicableMimeTypes: ['application/pdf'],
    weight: 2,
  },
  {
    pattern: Buffer.from('alert(', 'utf8'),
    name: 'JavaScript Alert',
    applicableMimeTypes: ['text/javascript', 'application/javascript'],
    weight: 1,
  },
  {
    pattern: Buffer.from('eval(', 'utf8'),
    name: 'JavaScript Eval',
    applicableMimeTypes: ['text/javascript', 'application/javascript'],
    weight: 2,
  },
  {
    pattern: Buffer.from('exec(', 'utf8'),
    name: 'Execution Command',
    applicableMimeTypes: ['text/x-php', 'application/x-php'],
    weight: 2,
  },
  {
    pattern: Buffer.from('system(', 'utf8'),
    name: 'System Command',
    applicableMimeTypes: ['text/x-php', 'application/x-php'],
    weight: 2,
  },
  {
    pattern: Buffer.from('#!/bin/', 'utf8'),
    name: 'Shell Shebang',
    applicableMimeTypes: ['text/x-shellscript'],
    weight: 1,
  },
  {
    pattern: Buffer.from('cmd.exe', 'utf8'),
    name: 'Windows Command',
    applicableMimeTypes: ['text/x-batch'],
    weight: 1,
  },
  {
    pattern: Buffer.from('DROP TABLE', 'utf8'),
    name: 'SQL Drop Command',
    applicableMimeTypes: ['application/sql'],
    weight: 3,
  },
  {
    pattern: Buffer.from('UNION SELECT', 'utf8'),
    name: 'SQL Union',
    applicableMimeTypes: ['application/sql'],
    weight: 3,
  },
];

/**
 * Result of suspicious pattern analysis.
 */
export interface SuspiciousPatternAnalysisResult {
  /** Whether any suspicious patterns were found */
  hasSuspicious: boolean;
  /** List of detected pattern names */
  patterns: string[];
  /** Suspicious score based on pattern weights */
  score: number;
}

/**
 * Analyzes a buffer for suspicious patterns.
 * @param buffer - The buffer to analyze
 * @param mimeType - Optional MIME type for context-aware filtering
 * @param maxAnalysisDepth - Maximum number of bytes to analyze (optional)
 * @param threshold - Threshold for suspicious score (optional, default 1)
 * @returns Analysis result containing detection status and found patterns
 */
export function analyzeSuspiciousPatterns(
  buffer: Buffer,
  mimeType?: string,
  maxAnalysisDepth?: number,
  threshold: number = 1,
): SuspiciousPatternAnalysisResult {
  const analysisDepth = maxAnalysisDepth
    ? Math.min(buffer.length, maxAnalysisDepth)
    : buffer.length;
  const analysisBuffer = buffer.subarray(0, analysisDepth);

  const applicablePatterns = SUSPICIOUS_PATTERNS.filter(
    (pattern) =>
      !pattern.applicableMimeTypes || (mimeType && pattern.applicableMimeTypes.includes(mimeType)),
  );

  const foundPatterns: string[] = [];
  let score = 0;

  for (const { pattern, name, weight = 1, regex } of applicablePatterns) {
    let matched = false;
    if (regex) {
      // Use regex for advanced matching
      const str = analysisBuffer.toString('utf8', 0, Math.min(analysisDepth, 1024)); // Limit string conversion for performance
      matched = regex.test(str);
    } else {
      // Use byte pattern matching
      matched = analysisBuffer.includes(pattern);
    }
    if (matched) {
      foundPatterns.push(name);
      score += weight;
    }
  }

  return {
    hasSuspicious: score >= threshold,
    patterns: foundPatterns,
    score,
  };
}

/**
 * Gets all available suspicious pattern names.
 * @returns Array of all pattern names
 */
export function getAllSuspiciousPatternNames(): string[] {
  return SUSPICIOUS_PATTERNS.map((pattern) => pattern.name);
}

/**
 * Gets the total number of suspicious patterns.
 * @returns Number of patterns
 */
export function getSuspiciousPatternCount(): number {
  return SUSPICIOUS_PATTERNS.length;
}

/**
 * Finds patterns by category based on name prefixes.
 * @param category - Category prefix to filter by (e.g., 'HTML', 'SQL', 'JavaScript')
 * @returns Array of matching patterns
 */
export function getPatternsByCategory(category: string): SuspiciousPattern[] {
  return SUSPICIOUS_PATTERNS.filter((pattern) =>
    pattern.name.toLowerCase().startsWith(category.toLowerCase()),
  );
}
