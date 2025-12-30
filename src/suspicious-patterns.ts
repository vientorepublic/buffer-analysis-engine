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
  // XSS and HTML injection patterns
  { pattern: Buffer.from('<script', 'utf8'), name: 'HTML Script Tag' },
  { pattern: Buffer.from('</script>', 'utf8'), name: 'HTML Script Close Tag' },
  { pattern: Buffer.from('<iframe', 'utf8'), name: 'HTML Iframe Tag' },
  { pattern: Buffer.from('<object', 'utf8'), name: 'HTML Object Tag' },
  { pattern: Buffer.from('<embed', 'utf8'), name: 'HTML Embed Tag' },
  { pattern: Buffer.from('onload=', 'utf8'), name: 'HTML Onload Event' },
  { pattern: Buffer.from('onerror=', 'utf8'), name: 'HTML Onerror Event' },
  { pattern: Buffer.from('onclick=', 'utf8'), name: 'HTML Onclick Event' },
  { pattern: Buffer.from('onmouseover=', 'utf8'), name: 'HTML Onmouseover Event' },
  { pattern: Buffer.from('document.cookie', 'utf8'), name: 'JavaScript Cookie Access' },
  { pattern: Buffer.from('localStorage', 'utf8'), name: 'JavaScript LocalStorage' },
  { pattern: Buffer.from('sessionStorage', 'utf8'), name: 'JavaScript SessionStorage' },

  // JavaScript/VBScript protocols and functions
  { pattern: Buffer.from('javascript:', 'utf8'), name: 'JavaScript Protocol' },
  { pattern: Buffer.from('vbscript:', 'utf8'), name: 'VBScript Protocol' },
  { pattern: Buffer.from('data:text/html', 'utf8'), name: 'Data URL HTML' },
  { pattern: Buffer.from('/JavaScript', 'utf8'), name: 'PDF JavaScript' },
  { pattern: Buffer.from('alert(', 'utf8'), name: 'JavaScript Alert' },
  { pattern: Buffer.from('confirm(', 'utf8'), name: 'JavaScript Confirm' },
  { pattern: Buffer.from('prompt(', 'utf8'), name: 'JavaScript Prompt' },
  { pattern: Buffer.from('eval(', 'utf8'), name: 'JavaScript Eval' },
  { pattern: Buffer.from('Function(', 'utf8'), name: 'JavaScript Function Constructor' },
  { pattern: Buffer.from('setTimeout(', 'utf8'), name: 'JavaScript SetTimeout' },
  { pattern: Buffer.from('setInterval(', 'utf8'), name: 'JavaScript SetInterval' },

  // Command execution patterns
  { pattern: Buffer.from('exec(', 'utf8'), name: 'Execution Command' },
  { pattern: Buffer.from('system(', 'utf8'), name: 'System Command' },
  { pattern: Buffer.from('shell_exec(', 'utf8'), name: 'Shell Exec Command' },
  { pattern: Buffer.from('passthru(', 'utf8'), name: 'Passthru Command' },
  { pattern: Buffer.from('popen(', 'utf8'), name: 'Popen Command' },
  { pattern: Buffer.from('proc_open(', 'utf8'), name: 'Proc Open Command' },
  { pattern: Buffer.from("require('child_process')", 'utf8'), name: 'Node.js Child Process' },
  { pattern: Buffer.from('child_process.exec', 'utf8'), name: 'Node.js Exec' },
  { pattern: Buffer.from('child_process.spawn', 'utf8'), name: 'Node.js Spawn' },

  // Shell and system patterns
  { pattern: Buffer.from('#!/bin/', 'utf8'), name: 'Shell Shebang' },
  { pattern: Buffer.from('#!/usr/bin/', 'utf8'), name: 'Shell Shebang' },
  { pattern: Buffer.from('cmd.exe', 'utf8'), name: 'Windows Command' },
  { pattern: Buffer.from('powershell', 'utf8'), name: 'PowerShell' },
  { pattern: Buffer.from('bash -c', 'utf8'), name: 'Bash Command' },
  { pattern: Buffer.from('sh -c', 'utf8'), name: 'Shell Command' },

  // SQL injection patterns
  { pattern: Buffer.from('DROP TABLE', 'utf8'), name: 'SQL Drop Command' },
  { pattern: Buffer.from('DROP DATABASE', 'utf8'), name: 'SQL Drop Database' },
  { pattern: Buffer.from('TRUNCATE TABLE', 'utf8'), name: 'SQL Truncate Table' },
  { pattern: Buffer.from('UNION SELECT', 'utf8'), name: 'SQL Union' },
  { pattern: Buffer.from('UNION ALL SELECT', 'utf8'), name: 'SQL Union All' },
  { pattern: Buffer.from('SELECT * FROM', 'utf8'), name: 'SQL Select All' },
  { pattern: Buffer.from('INSERT INTO', 'utf8'), name: 'SQL Insert' },
  { pattern: Buffer.from('UPDATE ', 'utf8'), name: 'SQL Update' },
  { pattern: Buffer.from('DELETE FROM', 'utf8'), name: 'SQL Delete' },
  { pattern: Buffer.from('-- ', 'utf8'), name: 'SQL Comment' },
  { pattern: Buffer.from('/*', 'utf8'), name: 'SQL Block Comment' },
  { pattern: Buffer.from('1=1', 'utf8'), name: 'SQL Tautology' },
  { pattern: Buffer.from('OR 1=1', 'utf8'), name: 'SQL OR Injection' },
  { pattern: Buffer.from('AND 1=1', 'utf8'), name: 'SQL AND Injection' },

  // PHP patterns
  { pattern: Buffer.from('<?php', 'utf8'), name: 'PHP Open Tag' },
  { pattern: Buffer.from('<?= ', 'utf8'), name: 'PHP Short Echo Tag' },
  { pattern: Buffer.from('eval(', 'utf8'), name: 'PHP Eval' },
  { pattern: Buffer.from('assert(', 'utf8'), name: 'PHP Assert' },
  { pattern: Buffer.from('create_function(', 'utf8'), name: 'PHP Create Function' },
  { pattern: Buffer.from('include(', 'utf8'), name: 'PHP Include' },
  { pattern: Buffer.from('require(', 'utf8'), name: 'PHP Require' },
  { pattern: Buffer.from('include_once(', 'utf8'), name: 'PHP Include Once' },
  { pattern: Buffer.from('require_once(', 'utf8'), name: 'PHP Require Once' },

  // Python patterns
  { pattern: Buffer.from('exec(', 'utf8'), name: 'Python Exec' },
  { pattern: Buffer.from('eval(', 'utf8'), name: 'Python Eval' },
  { pattern: Buffer.from('__import__(', 'utf8'), name: 'Python Import' },
  { pattern: Buffer.from('subprocess.', 'utf8'), name: 'Python Subprocess' },
  { pattern: Buffer.from('os.system(', 'utf8'), name: 'Python OS System' },
  { pattern: Buffer.from('os.popen(', 'utf8'), name: 'Python OS Popen' },

  // Encoding and obfuscation patterns
  { pattern: Buffer.from('base64', 'utf8'), name: 'Base64 Encoding' },
  { pattern: Buffer.from('atob(', 'utf8'), name: 'Base64 Decode' },
  { pattern: Buffer.from('btoa(', 'utf8'), name: 'Base64 Encode' },
  { pattern: Buffer.from('unescape(', 'utf8'), name: 'URL Unescape' },
  { pattern: Buffer.from('decodeURIComponent(', 'utf8'), name: 'URI Decode' },
  { pattern: Buffer.from('encodeURIComponent(', 'utf8'), name: 'URI Encode' },

  // Command injection operators
  { pattern: Buffer.from(';', 'utf8'), name: 'Command Separator' },
  { pattern: Buffer.from('|', 'utf8'), name: 'Pipe Operator' },
  { pattern: Buffer.from('&&', 'utf8'), name: 'AND Operator' },
  { pattern: Buffer.from('||', 'utf8'), name: 'OR Operator' },
  { pattern: Buffer.from('`', 'utf8'), name: 'Backtick Execution' },
  { pattern: Buffer.from('$(', 'utf8'), name: 'Command Substitution' },

  // File system patterns
  { pattern: Buffer.from('/etc/passwd', 'utf8'), name: 'Unix Passwd File' },
  { pattern: Buffer.from('/etc/shadow', 'utf8'), name: 'Unix Shadow File' },
  { pattern: Buffer.from('C:\\Windows\\System32', 'utf8'), name: 'Windows System Directory' },
  { pattern: Buffer.from('..\\..\\', 'utf8'), name: 'Directory Traversal' },
  { pattern: Buffer.from('../', 'utf8'), name: 'Directory Traversal' },
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
