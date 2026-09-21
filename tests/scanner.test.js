import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { scanTarget, isPathIgnored } from '../src/scanner.js';

test('isPathIgnored correctly flags ignored files and directories', () => {
  assert.equal(isPathIgnored('node_modules/express/index.js'), true);
  assert.equal(isPathIgnored('.git/config'), true);
  assert.equal(isPathIgnored('images/logo.png'), true);
  assert.equal(isPathIgnored('src/app.js'), false);
  assert.equal(isPathIgnored('custom/test.txt', ['custom/']), true);
});

test('scanTarget discovers leaks in directory and ignores clean files', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'secret-scrub-test-'));

  try {
    // Write clean file
    await fs.writeFile(
      path.join(tmpDir, 'main.js'),
      'console.log("Hello clean world!");\n'
    );

    // Write file with secret
    const dummyToken = ['ghp', '123456789012345678901234567890123456'].join('_');
    await fs.writeFile(
      path.join(tmpDir, 'secrets.js'),
      `const token = "${dummyToken}";\n`
    );

    // Write ignored image dummy
    await fs.writeFile(path.join(tmpDir, 'asset.png'), 'fake-binary');

    const result = await scanTarget(tmpDir);

    assert.equal(result.scannedCount, 2); // main.js and secrets.js
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].ruleId, 'github-pat-classic');
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});
