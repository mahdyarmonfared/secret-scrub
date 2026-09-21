import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { installPreCommitHook, uninstallPreCommitHook } from '../src/git.js';

test('installPreCommitHook writes hook file and uninstall removes it', async () => {
  const tmpRepo = await fs.mkdtemp(path.join(os.tmpdir(), 'secret-scrub-git-'));
  const gitDir = path.join(tmpRepo, '.git');
  await fs.mkdir(gitDir, { recursive: true });

  try {
    const { hookPath } = await installPreCommitHook(tmpRepo);
    const content = await fs.readFile(hookPath, 'utf-8');
    assert.ok(content.includes('SecretScrub Git Pre-Commit Hook'));

    const uninstalled = await uninstallPreCommitHook(tmpRepo);
    assert.equal(uninstalled, true);

    await assert.rejects(async () => {
      await fs.stat(hookPath);
    });
  } finally {
    await fs.rm(tmpRepo, { recursive: true, force: true });
  }
});
