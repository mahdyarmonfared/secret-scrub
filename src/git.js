import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs/promises';
import path from 'node:path';
import { detectSecretsInContent } from './detector.js';
import { isBinaryBuffer } from './utils.js';

const execFileAsync = promisify(execFile);

/**
 * Retrieve the list of files currently staged in Git index (Added, Copied, Modified).
 * @param {string} [cwd=process.cwd()]
 * @returns {Promise<string[]>}
 */
export async function getStagedFiles(cwd = process.cwd()) {
  try {
    const { stdout } = await execFileAsync(
      'git',
      ['diff', '--cached', '--name-only', '--diff-filter=ACM'],
      { cwd }
    );
    return stdout
      .split(/\r?\n/)
      .map((f) => f.trim())
      .filter(Boolean);
  } catch (err) {
    throw new Error(`Git error retrieving staged files: ${err.message}`);
  }
}

/**
 * Scan only the files currently staged for commit in the Git repository.
 * @param {object} [options={}]
 * @param {string} [options.cwd=process.cwd()]
 * @param {boolean} [options.enableEntropy=false]
 * @returns {Promise<{ findings: Array<object>, scannedCount: number, elapsedMs: number }>}
 */
export async function scanGitStaged(options = {}) {
  const startTime = Date.now();
  const cwd = options.cwd || process.cwd();
  const stagedFiles = await getStagedFiles(cwd);

  const findings = [];
  let scannedCount = 0;

  for (const relPath of stagedFiles) {
    const fullPath = path.resolve(cwd, relPath);
    try {
      const buffer = await fs.readFile(fullPath);
      if (isBinaryBuffer(buffer)) continue;

      const content = buffer.toString('utf-8');
      const fileFindings = detectSecretsInContent(content, relPath, {
        enableEntropy: options.enableEntropy,
      });

      findings.push(...fileFindings);
      scannedCount++;
    } catch {
      // File may have been unstaged or deleted
    }
  }

  return {
    findings,
    scannedCount,
    elapsedMs: Date.now() - startTime,
  };
}

/**
 * Find the nearest .git root directory.
 * @param {string} [startDir=process.cwd()]
 * @returns {Promise<string>}
 */
export async function findGitRoot(startDir = process.cwd()) {
  let current = path.resolve(startDir);
  while (true) {
    const gitPath = path.join(current, '.git');
    try {
      const stat = await fs.stat(gitPath);
      if (stat.isDirectory()) {
        return current;
      }
    } catch {
      // Continue search up
    }
    const parent = path.dirname(current);
    if (parent === current) {
      throw new Error('Not inside a Git repository (no .git folder found).');
    }
    current = parent;
  }
}

/**
 * Install a pre-commit hook into the current Git repository.
 * @param {string} [rootDir]
 * @returns {Promise<{ hookPath: string }>}
 */
export async function installPreCommitHook(rootDir) {
  const repoRoot = rootDir || (await findGitRoot());
  const hooksDir = path.join(repoRoot, '.git', 'hooks');
  const hookPath = path.join(hooksDir, 'pre-commit');

  await fs.mkdir(hooksDir, { recursive: true });

  const hookScript = `#!/usr/bin/env sh
# SecretScrub Git Pre-Commit Hook
# Prevents accidental commits of API keys, tokens, and credentials.

echo "🛡️  Running SecretScrub pre-commit scanner..."

if command -v secret-scrub >/dev/null 2>&1; then
  secret-scrub scan --staged
elif [ -f "./bin/secret-scrub.js" ]; then
  node "./bin/secret-scrub.js" scan --staged
elif command -v npx >/dev/null 2>&1; then
  npx --yes secret-scrub scan --staged
else
  echo "⚠️  secret-scrub not found in PATH or npx; skipping hook check."
  exit 0
fi

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "❌ Commit aborted by SecretScrub! Secrets or credentials detected in staged files."
  echo "💡 Remove or encrypt the sensitive credentials before committing."
  echo "   Use 'git commit --no-verify' only if you are absolutely sure."
  exit $EXIT_CODE
fi

exit 0
`;

  await fs.writeFile(hookPath, hookScript, { encoding: 'utf-8', mode: 0o755 });
  return { hookPath };
}

/**
 * Uninstall the pre-commit hook.
 * @param {string} [rootDir]
 * @returns {Promise<boolean>}
 */
export async function uninstallPreCommitHook(rootDir) {
  const repoRoot = rootDir || (await findGitRoot());
  const hookPath = path.join(repoRoot, '.git', 'hooks', 'pre-commit');

  try {
    await fs.unlink(hookPath);
    return true;
  } catch {
    return false;
  }
}
