import { RULES, SEVERITY } from './rules.js';
import { calculateShannonEntropy, isHighEntropySecret } from './entropy.js';
import { redactSecret, isFalsePositive } from './utils.js';

/**
 * Scan a block of text line-by-line against secret detection rules.
 * @param {string} content - File or string content to inspect
 * @param {string} filePath - Relative or absolute path for attribution
 * @param {object} [options={}] - Inspection options
 * @param {boolean} [options.enableEntropy=false] - Also flag generic high-entropy strings
 * @param {string[]} [options.disabledRules=[]] - List of rule IDs to skip
 * @returns {Array<object>} - List of detected secret findings
 */
export function detectSecretsInContent(content, filePath = 'unknown', options = {}) {
  const {
    enableEntropy = false,
    disabledRules = [],
  } = options;

  const findings = [];
  const lines = content.split(/\r?\n/);
  const activeRules = RULES.filter((r) => !disabledRules.includes(r.id));

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex];
    const lineNumber = lineIndex + 1;

    // Skip empty or excessively long minified lines (> 5000 chars)
    if (!line || line.length > 5000) continue;

    for (const rule of activeRules) {
      const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
      let match;

      while ((match = regex.exec(line)) !== null) {
        const fullMatch = match[0];
        const secretCandidate = rule.matchGroup ? match[rule.matchGroup] : fullMatch;

        if (!secretCandidate) continue;

        // Verify false positive heuristics
        if (isFalsePositive(secretCandidate, line)) {
          continue;
        }

        const entropy = calculateShannonEntropy(secretCandidate);

        // If rule specifies an entropy floor, enforce it
        if (rule.requiresEntropy && rule.minEntropy && entropy < rule.minEntropy) {
          continue;
        }

        const column = match.index + 1;
        const maskedMatch = redactSecret(secretCandidate);

        findings.push({
          ruleId: rule.id,
          ruleName: rule.name,
          provider: rule.provider,
          severity: rule.severity,
          description: rule.description,
          filePath,
          lineNumber,
          column,
          rawMatch: secretCandidate,
          maskedMatch,
          lineSnippet: line.trim(),
          entropy,
        });
      }
    }

    // Optional generic standalone entropy scanner
    if (enableEntropy) {
      // Look for standalone tokens: sequences of alphanumeric, underscore, hyphen or plus
      const tokens = line.matchAll(/\b([A-Za-z0-9+/=_-]{20,80})\b/g);
      for (const tokenMatch of tokens) {
        const token = tokenMatch[1];
        if (isFalsePositive(token, line)) continue;

        // Exclude tokens already caught by explicit rules on this line
        const alreadyMatched = findings.some(
          (f) => f.lineNumber === lineNumber && f.rawMatch === token
        );
        if (alreadyMatched) continue;

        const entropy = calculateShannonEntropy(token);
        if (entropy >= 4.5) {
          findings.push({
            ruleId: 'high-entropy-string',
            ruleName: 'Unidentified High-Entropy Token',
            provider: 'Heuristic',
            severity: SEVERITY.MEDIUM,
            description: 'Unclassified random token with high Shannon entropy.',
            filePath,
            lineNumber,
            column: tokenMatch.index + 1,
            rawMatch: token,
            maskedMatch: redactSecret(token),
            lineSnippet: line.trim(),
            entropy,
          });
        }
      }
    }
  }

  return findings;
}
