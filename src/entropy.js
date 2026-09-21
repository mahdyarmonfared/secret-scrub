/**
 * Shannon Entropy calculation for estimating cryptographic randomness.
 * Standard formula: H(X) = - sum(P(x) * log2(P(x)))
 */

/**
 * Calculate the Shannon entropy of a string (bits per character).
 * @param {string} str - Input text
 * @returns {number} - Entropy value (0.0 to ~8.0)
 */
export function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;

  const frequencies = new Map();
  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }

  const length = str.length;
  let entropy = 0;

  for (const count of frequencies.values()) {
    const probability = count / length;
    entropy -= probability * Math.log2(probability);
  }

  return Number(entropy.toFixed(3));
}

/**
 * Determine if a string looks like a high-entropy secret token.
 * Typically tokens have length >= 16 and entropy >= 4.2 bits/char.
 * @param {string} str - Candidate string
 * @param {number} [threshold=4.2] - Entropy threshold
 * @param {number} [minLength=16] - Minimum string length
 * @returns {boolean}
 */
export function isHighEntropySecret(str, threshold = 4.2, minLength = 16) {
  if (!str || str.length < minLength) return false;

  // Skip strings with repetitive whitespace or obvious formatting
  if (/\s/.test(str)) return false;

  const entropy = calculateShannonEntropy(str);
  return entropy >= threshold;
}
