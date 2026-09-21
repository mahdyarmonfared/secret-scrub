import { SEVERITY } from './rules.js';

/**
 * Mask a secret string so it is safe to display in terminal outputs or logs.
 * Example: 'AKIA1234567890ABCDEF' -> 'AKIA12...CDEF'
 * @param {string} secret - Plaintext secret
 * @param {number} [visibleChars=4] - Number of characters to preserve at start and end
 * @returns {string} - Masked string
 */
export function redactSecret(secret, visibleChars = 4) {
  if (!secret) return '';
  const str = String(secret);
  if (str.length <= visibleChars * 2) {
    return '*'.repeat(str.length);
  }
  const prefix = str.slice(0, visibleChars);
  const suffix = str.slice(-visibleChars);
  const hiddenCount = Math.min(16, str.length - visibleChars * 2);
  return `${prefix}${'•'.repeat(hiddenCount)}${suffix}`;
}

/**
 * Detect whether a buffer or string represents binary file content.
 * @param {Buffer|Uint8Array} buffer
 * @returns {boolean}
 */
export function isBinaryBuffer(buffer) {
  if (!buffer || buffer.length === 0) return false;
  const sampleSize = Math.min(buffer.length, 1024);
  for (let i = 0; i < sampleSize; i++) {
    if (buffer[i] === 0) {
      return true;
    }
  }
  return false;
}

/**
 * Heuristics to reject obvious false positives, documentation examples, and mock data.
 * @param {string} matched
 * @param {string} line
 * @returns {boolean}
 */
export function isFalsePositive(matched, line) {
  const lowerMatched = matched.toLowerCase();
  const lowerLine = line.toLowerCase();

  // Obvious placeholder words
  const placeholders = [
    'example',
    'placeholder',
    'your_api_key',
    'your-api-key',
    'your_token',
    'your-token',
    'dummy',
    'fake',
    'sample',
    'my-secret',
    'my_secret',
    'mysecret',
    'changeme',
    'xxxxxxxx',
    '00000000',
    '11111111',
    'abcdefgh',
    'test_key',
    'test-key',
  ];

  for (const ph of placeholders) {
    if (lowerMatched.includes(ph)) return true;
  }

  // Template variables (e.g. ${AWS_ACCESS_KEY}, <%= token %>, {{ secret }})
  if (/(\$\{[A-Za-z0-9_]+\}|\{\{[A-Za-z0-9_]+\}|<%.*?%>)/.test(matched)) {
    return true;
  }

  // Common markdown / comment indicators of example code
  if (lowerLine.includes('example:') || lowerLine.includes('e.g.') || lowerLine.includes('replace with')) {
    return true;
  }

  return false;
}

/**
 * Severity ranking weights for comparison and exit code decisions.
 */
export const SEVERITY_WEIGHTS = {
  [SEVERITY.CRITICAL]: 4,
  [SEVERITY.HIGH]: 3,
  [SEVERITY.MEDIUM]: 2,
  [SEVERITY.LOW]: 1,
};

export function getSeverityWeight(sev) {
  return SEVERITY_WEIGHTS[sev] || 0;
}
