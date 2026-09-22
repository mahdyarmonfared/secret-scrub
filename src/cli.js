import { Command } from 'commander';
import chalk from 'chalk';
import Table from 'cli-table3';
import ora from 'ora';
import { scanTarget } from './scanner.js';
import { scanGitStaged, installPreCommitHook, uninstallPreCommitHook } from './git.js';
import { formatTerminalReport, formatJsonReport } from './reporter.js';
import { RULES, SEVERITY } from './rules.js';
import { getSeverityWeight, SEVERITY_WEIGHTS } from './utils.js';
import { startWebServer } from './server.js';

export function createCli() {
  const program = new Command();

  program
    .name('secret-scrub')
    .description('Ultra-fast, zero-leak pre-commit secret scanner with entropy analysis.')
    .version('1.0.0');

  // Command: scan [path]
  program
    .command('scan [targetPath]')
    .description('Scan files, directories, or staged git files for secrets')
    .option('-s, --staged', 'Scan only Git staged files (fast pre-commit check)', false)
    .option('-e, --entropy', 'Enable Shannon entropy analysis for unknown tokens', false)
    .option('-i, --ignore <patterns...>', 'Additional glob patterns to ignore', [])
    .option('-m, --min-severity <level>', 'Minimum severity to trigger exit failure (low, medium, high, critical)', 'high')
    .option('-j, --json', 'Output findings as standardized JSON', false)
    .action(async (targetPath = '.', options) => {
      const isJson = options.json;
      let spinner;

      if (!isJson && process.stdout.isTTY) {
        spinner = ora({
          text: options.staged ? 'Scanning Git staged files for secrets...' : `Scanning ${chalk.bold(targetPath)} for secrets...`,
          color: 'magenta',
        }).start();
      }

      try {
        let result;
        if (options.staged) {
          result = await scanGitStaged({
            enableEntropy: options.entropy,
          });
        } else {
          result = await scanTarget(targetPath, {
            enableEntropy: options.entropy,
            customIgnorePatterns: options.ignore,
          });
        }

        if (spinner) {
          spinner.stop();
        }

        if (isJson) {
          console.log(formatJsonReport(result));
        } else {
          console.log(formatTerminalReport(result));
        }

        // Determine exit code based on min-severity threshold
        const thresholdWeight = SEVERITY_WEIGHTS[options.minSeverity.toLowerCase()] || SEVERITY_WEIGHTS[SEVERITY.HIGH];
        const hasFailingFindings = result.findings.some(
          (f) => getSeverityWeight(f.severity) >= thresholdWeight
        );

        if (hasFailingFindings) {
          process.exit(1);
        }
      } catch (err) {
        if (spinner) spinner.fail('Scan failed');
        console.error(chalk.red(`\n❌ Error: ${err.message}`));
        process.exit(2);
      }
    });

  // Command group: hook
  const hookCommand = program
    .command('hook')
    .description('Manage Git pre-commit hooks for automatic secret scanning');

  hookCommand
    .command('install')
    .description('Install SecretScrub pre-commit hook into current Git repository')
    .action(async () => {
      try {
        const { hookPath } = await installPreCommitHook();
        console.log(chalk.green.bold('\n✅ SecretScrub pre-commit hook installed successfully!'));
        console.log(chalk.gray(`   Hook file: ${hookPath}`));
        console.log(chalk.white('   Git commits will now be automatically guarded against secret leaks.\n'));
      } catch (err) {
        console.error(chalk.red(`\n❌ Failed to install Git hook: ${err.message}\n`));
        process.exit(1);
      }
    });

  hookCommand
    .command('uninstall')
    .description('Remove SecretScrub pre-commit hook from current Git repository')
    .action(async () => {
      try {
        const removed = await uninstallPreCommitHook();
        if (removed) {
          console.log(chalk.yellow.bold('\n🗑️  SecretScrub pre-commit hook uninstalled.\n'));
        } else {
          console.log(chalk.gray('\nℹ️  No pre-commit hook was found to remove.\n'));
        }
      } catch (err) {
        console.error(chalk.red(`\n❌ Failed to uninstall Git hook: ${err.message}\n`));
        process.exit(1);
      }
    });

  hookCommand
    .command('run')
    .description('Run the pre-commit hook verification check manually')
    .action(async () => {
      const result = await scanGitStaged();
      console.log(formatTerminalReport(result));
      const hasCritical = result.findings.some(
        (f) => f.severity === SEVERITY.CRITICAL || f.severity === SEVERITY.HIGH
      );
      if (hasCritical) {
        process.exit(1);
      }
    });

  // Command: rules
  program
    .command('rules')
    .description('List all built-in secret detection signatures and severities')
    .action(() => {
      console.log('');
      console.log(chalk.bold.hex('#7C3AED')(' 🛡️  SECRETSCRUB — Supported Detection Rules'));
      console.log(chalk.gray('━'.repeat(68)));

      const table = new Table({
        head: [
          chalk.white.bold('ID'),
          chalk.white.bold('Provider'),
          chalk.white.bold('Severity'),
          chalk.white.bold('Description'),
        ],
        colWidths: [26, 16, 12, 36],
        wordWrap: true,
      });

      for (const rule of RULES) {
        const sevColor =
          rule.severity === SEVERITY.CRITICAL
            ? chalk.red.bold(rule.severity)
            : rule.severity === SEVERITY.HIGH
            ? chalk.hex('#FF5722').bold(rule.severity)
            : chalk.yellow(rule.severity);

        table.push([chalk.cyan(rule.id), rule.provider, sevColor, rule.description]);
      }

      console.log(table.toString());
      console.log(chalk.gray(`\n Total active signatures: ${RULES.length}\n`));
    });

  // Command: web [port]
  program
    .command('web [port]')
    .description('Launch the browser-based SecretScrub Security Playground locally')
    .option('-p, --port <number>', 'Server listening port', (v) => parseInt(v, 10), 3000)
    .action(async (portArg, options) => {
      const port = portArg ? parseInt(portArg, 10) : (options.port || 3000);
      await startWebServer({ port });
    });

  program
    .option('--web [port]', 'Launch the browser-based SecretScrub Security Playground locally');

  return program;
}

