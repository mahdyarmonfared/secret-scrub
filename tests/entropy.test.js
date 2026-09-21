import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateShannonEntropy, isHighEntropySecret } from '../src/entropy.js';

test('calculateShannonEntropy returns 0 for empty string', () => {
  assert.equal(calculateShannonEntropy(''), 0);
});

test('calculateShannonEntropy returns 0 for single repeated character', () => {
  assert.equal(calculateShannonEntropy('aaaaaaaaaaaa'), 0);
});

test('calculateShannonEntropy correctly computes entropy for varied strings', () => {
  // Low entropy pattern
  const low = calculateShannonEntropy('abcabcabcabc');
  assert.ok(low < 2.0, `Expected low entropy, got ${low}`);

  // High entropy pseudo-random base64 string
  const high = calculateShannonEntropy('x8K9mP2qL7vR4wT1zY6bC0nF3jS5hA9');
  assert.ok(high > 4.5, `Expected high entropy > 4.5, got ${high}`);
});

test('isHighEntropySecret identifies random tokens above threshold', () => {
  const token = 'c2lnbi1rZXktYjRhYjcwZjE2MDIw';
  assert.equal(isHighEntropySecret(token, 3.5, 16), true);

  // Repetitive or simple string
  const notToken = 'user_name_account_id_profile';
  assert.equal(isHighEntropySecret(notToken, 4.5, 16), false);
});
