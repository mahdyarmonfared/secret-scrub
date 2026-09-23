import test from 'node:test';
import assert from 'node:assert/strict';
import { startWebServer } from '../src/server.js';

test('startWebServer serves SecretScrub web playground on port', async () => {
  const testPort = 3799;
  const server = await startWebServer({ port: testPort });

  try {
    const res = await fetch(`http://localhost:${testPort}/`);
    assert.equal(res.status, 200);

    const contentType = res.headers.get('content-type');
    assert.ok(contentType.includes('text/html'));

    const html = await res.text();
    assert.ok(html.includes('SecretScrub'));
    assert.ok(html.includes('Security Findings'));

    // Check style.css
    const cssRes = await fetch(`http://localhost:${testPort}/style.css`);
    assert.equal(cssRes.status, 200);

    // Check GET /api/rules
    const rulesRes = await fetch(`http://localhost:${testPort}/api/rules`);
    assert.equal(rulesRes.status, 200);
    const rulesData = await rulesRes.json();
    assert.equal(rulesData.total, 18);
    assert.ok(Array.isArray(rulesData.rules));
    assert.ok(rulesData.rules.some((r) => r.id === 'aws-access-key-id'));

    // Check POST /api/scan
    const dummyKey = ['AKIA', '1234567890ABCDEF'].join('');
    const scanRes = await fetch(`http://localhost:${testPort}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: `const key = "${dummyKey}";` }),
    });
    assert.equal(scanRes.status, 200);
    const scanData = await scanRes.json();
    assert.equal(scanData.totalLeaks, 1);
    assert.equal(scanData.findings[0].ruleId, 'aws-access-key-id');

    // Check 404
    const notFoundRes = await fetch(`http://localhost:${testPort}/non-existent.xyz`);
    assert.equal(notFoundRes.status, 404);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
