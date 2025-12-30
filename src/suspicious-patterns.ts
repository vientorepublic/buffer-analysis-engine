/**
 * Suspicious pattern definitions and analysis functions for buffer security analysis.
 * This module contains patterns for detecting various security threats including XSS,
 * SQL injection, command injection, and other malicious content.
 */

/**
 * Represents a suspicious pattern with its byte signature and descriptive name.
 */
export interface SuspiciousPattern {
  /** The byte pattern to search for */
  pattern: Buffer;
  /** Human-readable name of the pattern */
  name: string;
}

/**
 * Collection of suspicious patterns organized by category.
 * Each pattern represents a potential security threat that should be flagged during buffer analysis.
 */
export const SUSPICIOUS_PATTERNS: SuspiciousPattern[] = [
  { pattern: Buffer.from('<script', 'utf8'), name: 'HTML Script Tag' },
  { pattern: Buffer.from('javascript:', 'utf8'), name: 'JavaScript Protocol' },
  { pattern: Buffer.from('vbscript:', 'utf8'), name: 'VBScript Protocol' },
  { pattern: Buffer.from('/JavaScript', 'utf8'), name: 'PDF JavaScript' },
  { pattern: Buffer.from('alert(', 'utf8'), name: 'JavaScript Alert' },
  { pattern: Buffer.from('eval(', 'utf8'), name: 'JavaScript Eval' },
  { pattern: Buffer.from('exec(', 'utf8'), name: 'Execution Command' },
  { pattern: Buffer.from('system(', 'utf8'), name: 'System Command' },
  { pattern: Buffer.from('#!/bin/', 'utf8'), name: 'Shell Shebang' },
  { pattern: Buffer.from('cmd.exe', 'utf8'), name: 'Windows Command' },
  { pattern: Buffer.from('DROP TABLE', 'utf8'), name: 'SQL Drop Command' },
  { pattern: Buffer.from('UNION SELECT', 'utf8'), name: 'SQL Union' },
];

/**
 * Result of suspicious pattern analysis.
 */
export interface SuspiciousPatternAnalysisResult {
  /** Whether any suspicious patterns were found */
  hasSuspicious: boolean;
  /** List of detected pattern names */
  patterns: string[];
}

/**
 * Analyzes a buffer for suspicious patterns.
 * @param buffer - The buffer to analyze
 * @param maxAnalysisDepth - Maximum number of bytes to analyze (optional)
 * @returns Analysis result containing detection status and found patterns
 */
export function analyzeSuspiciousPatterns(
  buffer: Buffer,
  maxAnalysisDepth?: number,
): SuspiciousPatternAnalysisResult {
  const analysisDepth = maxAnalysisDepth
    ? Math.min(buffer.length, maxAnalysisDepth)
    : buffer.length;
  const analysisBuffer = buffer.subarray(0, analysisDepth);

  const foundPatterns: string[] = [];
  for (const { pattern, name } of SUSPICIOUS_PATTERNS) {
    if (analysisBuffer.includes(pattern)) {
      foundPatterns.push(name);
    }
  }

  return {
    hasSuspicious: foundPatterns.length > 0,
    patterns: foundPatterns,
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
