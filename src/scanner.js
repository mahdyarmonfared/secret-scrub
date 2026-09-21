import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { detectSecretsInContent } from './detector.js';
import { isBinaryBuffer } from './utils.js';

const DEFAULT_IGNORED_DIRS = new Set([
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  'dist',
  'build',
  'coverage',
  '.next',
  '.nuxt',
  '.cache',
  '.venv',
  'venv',
  'vendor',
]);

const DEFAULT_IGNORED_EXTS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.svg',
  '.pdf', '.zip', '.tar', '.gz', '.7z', '.rar',
  '.woff', '.woff2', '.ttf', '.eot',
  '.mp4', '.mp3', '.mov', '.avi',
  '.wasm', '.exe', '.bin', '.so', '.dylib', '.dll',
  '.lock',
]);

/**
 * Load ignore patterns from an ignore file (.secretscrubignore or .gitignore).
 * @param {string} filePath
 * @returns {Promise<string[]>}
 */
export async function loadIgnoreFile(filePath) {
  try {
    const raw = await fs.readFile(filePath, 'utf-8');
    return raw
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'));
  } catch {
    return [];
  }
}

/**
 * Check whether a relative path matches simple ignore patterns.
 * @param {string} relPath
 * @param {string[]} patterns
 * @returns {boolean}
 */
export function isPathIgnored(relPath, patterns = []) {
  const normalized = relPath.replace(/\\/g, '/');
  const basename = path.basename(normalized);
  const ext = path.extname(normalized).toLowerCase();

  if (DEFAULT_IGNORED_EXTS.has(ext)) return true;

  const parts = normalized.split('/');
  for (const part of parts) {
    if (DEFAULT_IGNORED_DIRS.has(part)) return true;
  }

  for (const pattern of patterns) {
    const cleanPattern = pattern.replace(/^\/+|\/+$/g, '');
    if (!cleanPattern) continue;

    if (cleanPattern.startsWith('*.')) {
      const matchExt = cleanPattern.slice(1).toLowerCase();
      if (normalized.toLowerCase().endsWith(matchExt)) return true;
    } else if (normalized === cleanPattern || normalized.startsWith(cleanPattern + '/')) {
      return true;
    } else if (basename === cleanPattern) {
      return true;
    }
  }

  return false;
}

/**
 * Recursively scan a target directory or individual file for secrets.
 * @param {string} targetPath - Path to directory or file
 * @param {object} [options={}]
 * @param {boolean} [options.enableEntropy=false]
 * @param {string[]} [options.customIgnorePatterns=[]]
 * @param {function} [options.onFileScanned] - Callback for progress reporting
 * @returns {Promise<{ findings: Array<object>, scannedCount: number, elapsedMs: number }>}
 */
export async function scanTarget(targetPath, options = {}) {
  const startTime = Date.now();
  const absTarget = path.resolve(targetPath);
  const {
    enableEntropy = false,
    customIgnorePatterns = [],
    onFileScanned,
  } = options;

  // Attempt to load .secretscrubignore from target directory or current dir
  const dirRoot = (await fs.stat(absTarget)).isDirectory() ? absTarget : path.dirname(absTarget);
  const scrubIgnore = await loadIgnoreFile(path.join(dirRoot, '.secretscrubignore'));
  const gitIgnore = await loadIgnoreFile(path.join(dirRoot, '.gitignore'));
  const allIgnorePatterns = [...scrubIgnore, ...gitIgnore, ...customIgnorePatterns];

  const filesToScan = [];

  const stat = await fs.stat(absTarget);
  if (stat.isFile()) {
    filesToScan.push(absTarget);
  } else if (stat.isDirectory()) {
    await collectFiles(absTarget, absTarget, allIgnorePatterns, filesToScan);
  }

  const allFindings = [];
  let scannedCount = 0;

  for (const filePath of filesToScan) {
    try {
      // Read initial buffer to test if binary
      const fd = await fs.open(filePath, 'r');
      const sampleBuf = Buffer.alloc(1024);
      const { bytesRead } = await fd.read(sampleBuf, 0, 1024, 0);
      await fd.close();

      if (isBinaryBuffer(sampleBuf.subarray(0, bytesRead))) {
        continue;
      }

      const content = await fs.readFile(filePath, 'utf-8');
      const relPath = path.relative(process.cwd(), filePath);
      const findings = detectSecretsInContent(content, relPath, { enableEntropy });

      allFindings.push(...findings);
      scannedCount++;

      if (typeof onFileScanned === 'function') {
        onFileScanned(relPath, findings.length);
      }
    } catch {
      // Skip unreadable files (permission errors, broken symlinks, etc.)
    }
  }

  return {
    findings: allFindings,
    scannedCount,
    elapsedMs: Date.now() - startTime,
  };
}

/**
 * Recursive filesystem crawler with ignore filtering.
 */
async function collectFiles(currentDir, rootDir, ignorePatterns, results) {
  let entries;
  try {
    entries = await fs.readdir(currentDir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = path.join(currentDir, entry.name);
    const relPath = path.relative(rootDir, fullPath);

    if (isPathIgnored(relPath, ignorePatterns)) {
      continue;
    }

    if (entry.isDirectory()) {
      await collectFiles(fullPath, rootDir, ignorePatterns, results);
    } else if (entry.isFile()) {
      results.push(fullPath);
    }
  }
}
