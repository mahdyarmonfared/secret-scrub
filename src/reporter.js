import chalk from 'chalk';
import Table from 'cli-table3';
import { SEVERITY } from './rules.js';

/**
 * Format findings and summary as a beautiful terminal output with tables and badges.
 * @param {object} scanResult
 * @param {Array<object>} scanResult.findings
 * @param {number} scanResult.scannedCount
 * @param {number} scanResult.elapsedMs
 * @param {object} [options={}]
 * @returns {string}
 */
export function formatTerminalReport(scanResult, options = {}) {
  const { findings, scannedCount, elapsedMs } = scanResult;
  const lines = [];

  const severityBadges = {
    [SEVERITY.CRITICAL]: chalk.bgRed.white.bold(' CRITICAL '),
    [SEVERITY.HIGH]: chalk.bgHex('#FF5722').white.bold('   HIGH   '),
    [SEVERITY.MEDIUM]: chalk.bgYellow.black.bold('  MEDIUM  '),
    [SEVERITY.LOW]: chalk.bgCyan.black.bold('   LOW    '),
  };

  lines.push('');
  lines.push(
    chalk.bold.hex('#7C3AED')(' 🛡️  SECRETSCRUB') +
    chalk.gray(' — Pre-Commit & Codebase Credential Guard')
  );
  lines.push(chalk.gray('━'.repeat(68)));

  if (findings.length === 0) {
    lines.push('');
    lines.push(
      chalk.green.bold('  ✨ Clean Scan! No exposed secrets or credentials found.')
    );
    lines.push(
      chalk.gray(`  Inspected ${chalk.bold(scannedCount)} files in ${chalk.bold(elapsedMs)}ms.`)
    );
    lines.push('');
    return lines.join('\n');
  }

  // Findings Table
  const table = new Table({
    head: [
      chalk.white.bold('Severity'),
      chalk.white.bold('Rule / Provider'),
      chalk.white.bold('Location'),
      chalk.white.bold('Masked Match'),
    ],
    colWidths: [12, 24, 30, 22],
    wordWrap: true,
    style: {
      head: [],
      border: ['gray'],
    },
  });

  for (const finding of findings) {
    const badge = severityBadges[finding.severity] || finding.severity;
    const ruleInfo = `${finding.ruleName}\n${chalk.gray(finding.provider)}`;
    const location = `${chalk.cyan(finding.filePath)}:${chalk.yellow(finding.lineNumber)}:${chalk.gray(finding.column)}`;
    const masked = chalk.red(finding.maskedMatch);

    table.push([badge, ruleInfo, location, masked]);
  }

  lines.push(table.toString());
  lines.push('');

  // Code Snippet Details for top findings (up to 5)
  lines.push(chalk.bold.underline('🔎 Finding Snippets:'));
  const sampleFindings = findings.slice(0, 5);
  for (const f of sampleFindings) {
    lines.push('');
    lines.push(
      `  ${chalk.gray('•')} ${chalk.cyan(f.filePath)}:${chalk.yellow(f.lineNumber)} ${chalk.gray('(' + f.ruleName + ')')}`
    );
    lines.push(`    ${chalk.gray(f.lineNumber.toString().padStart(4, ' ') + ' |')} ${highlightSnippet(f.lineSnippet, f.rawMatch)}`);
  }

  if (findings.length > 5) {
    lines.push('');
    lines.push(chalk.gray(`  ... and ${findings.length - 5} more finding(s).`));
  }

  // Summary Metrics
  const criticalCount = findings.filter((f) => f.severity === SEVERITY.CRITICAL).length;
  const highCount = findings.filter((f) => f.severity === SEVERITY.HIGH).length;
  const mediumCount = findings.filter((f) => f.severity === SEVERITY.MEDIUM).length;
  const lowCount = findings.filter((f) => f.severity === SEVERITY.LOW).length;

  lines.push('');
  lines.push(chalk.gray('─'.repeat(68)));
  lines.push(chalk.bold('📊 Summary:'));
  lines.push(
    `   Files Scanned: ${chalk.bold(scannedCount)}   |   Time: ${chalk.bold(elapsedMs)}ms`
  );
  lines.push(
    `   Total Findings: ${chalk.red.bold(findings.length)}  (` +
    [
      criticalCount ? chalk.red.bold(`${criticalCount} Critical`) : null,
      highCount ? chalk.hex('#FF5722').bold(`${highCount} High`) : null,
      mediumCount ? chalk.yellow.bold(`${mediumCount} Medium`) : null,
      lowCount ? chalk.cyan.bold(`${lowCount} Low`) : null,
    ].filter(Boolean).join(', ') + ')'
  );
  lines.push(chalk.gray('─'.repeat(68)));
  lines.push(
    chalk.yellow.bold('⚠️  Action Required: ') +
    chalk.white('Rotate or move credentials to encrypted environment variables before pushing!')
  );
  lines.push('');

  return lines.join('\n');
}

/**
 * Format scan results as standardized JSON string.
 * @param {object} scanResult
 * @returns {string}
 */
export function formatJsonReport(scanResult) {
  const output = {
    schemaVersion: '1.0.0',
    tool: 'secret-scrub',
    timestamp: new Date().toISOString(),
    metrics: {
      filesScanned: scanResult.scannedCount,
      elapsedMilliseconds: scanResult.elapsedMs,
      findingsCount: scanResult.findings.length,
      criticalCount: scanResult.findings.filter((f) => f.severity === SEVERITY.CRITICAL).length,
      highCount: scanResult.findings.filter((f) => f.severity === SEVERITY.HIGH).length,
      mediumCount: scanResult.findings.filter((f) => f.severity === SEVERITY.MEDIUM).length,
      lowCount: scanResult.findings.filter((f) => f.severity === SEVERITY.LOW).length,
    },
    findings: scanResult.findings.map((f) => ({
      ruleId: f.ruleId,
      ruleName: f.ruleName,
      provider: f.provider,
      severity: f.severity,
      filePath: f.filePath,
      lineNumber: f.lineNumber,
      column: f.column,
      maskedMatch: f.maskedMatch,
      entropy: f.entropy,
    })),
  };

  return JSON.stringify(output, null, 2);
}

function highlightSnippet(snippet, match) {
  if (!match) return snippet;
  const idx = snippet.indexOf(match);
  if (idx === -1) return snippet;

  const before = snippet.slice(0, idx);
  const matched = chalk.bgRed.white.bold(snippet.slice(idx, idx + match.length));
  const after = snippet.slice(idx + match.length);
  return `${before}${matched}${after}`;
}
