import test from 'node:test';
import assert from 'node:assert/strict';
import { detectSecretsInContent } from '../src/detector.js';
import { SEVERITY } from '../src/rules.js';

test('detects AWS Access Key ID and Secret Access Key', () => {
  const dummyAwsKey = ['AKIA', '1234567890ABCDEF'].join('');
  const dummyAwsSecret = ['aws_secret_access_key', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCY1234567890'].join(' = ');
  const content = `const awsKey = "${dummyAwsKey}";\nconst awsSecret = "${dummyAwsSecret}";`;
  const findings = detectSecretsInContent(content, 'config.js');

  const awsId = findings.find((f) => f.ruleId === 'aws-access-key-id');
  assert.ok(awsId, 'Expected AWS Access Key ID to be found');
  assert.equal(awsId.severity, SEVERITY.CRITICAL);
  assert.equal(awsId.lineNumber, 1);
  assert.ok(awsId.maskedMatch.includes('••••'));

  const awsSecret = findings.find((f) => f.ruleId === 'aws-secret-access-key');
  assert.ok(awsSecret, 'Expected AWS Secret Access Key to be found');
  assert.equal(awsSecret.lineNumber, 2);
});

test('detects GitHub Personal Access Tokens (Classic and Fine-Grained)', () => {
  const dummyGhp = ['ghp', '123456789012345678901234567890123456'].join('_');
  const dummyPat = ['github', 'pat', '11ABCD1234ef995678ijkl_MNOP9876QRST5432UVWX1098YZAB7654CDEF3210GHIJ9876KLMN5432'].join('_');
  const content = `export const GITHUB_TOKEN = "${dummyGhp}";\nexport const FINE_GRAINED = "${dummyPat}";`;
  const findings = detectSecretsInContent(content, 'github.ts');

  assert.equal(findings.length, 2);
  assert.equal(findings[0].ruleId, 'github-pat-classic');
  assert.equal(findings[1].ruleId, 'github-pat-fine-grained');
});

test('detects OpenAI and Anthropic API Keys', () => {
  const dummyOai = ['sk', 'proj', '9Qz8W2eR4tY6uI1oP3aS5dF7gH9jK2lZ4xV6cN8mB0vC2xZ4lK6jH8gF0dSa'].join('-');
  const dummyClaude = ['sk', 'ant', 'api03-9Qz8W2eR4tY6uI1oP3aS5dF7gH9jK2lZ4xV6cN8mB0vC2xZ4lK6jH8gF0dSa'].join('-');
  const content = `const openai = new OpenAI({ apiKey: "${dummyOai}" });\nconst claude = "${dummyClaude}";`;
  const findings = detectSecretsInContent(content, 'ai.js');

  const openAiFinding = findings.find((f) => f.ruleId === 'openai-api-key');
  assert.ok(openAiFinding, 'Expected OpenAI API Key finding');
  assert.equal(openAiFinding.provider, 'OpenAI');

  const anthropicFinding = findings.find((f) => f.ruleId === 'anthropic-api-key');
  assert.ok(anthropicFinding, 'Expected Anthropic API Key finding');
  assert.equal(anthropicFinding.provider, 'Anthropic');
});

test('detects Stripe live keys and Private Key blocks', () => {
  const dummyStripe = ['sk', 'live', '51AbcDef1234567890GhiJklMnoPqr'].join('_');
  const content = `const stripe = Stripe('${dummyStripe}');\nconst privateKey = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA0...";`;
  const findings = detectSecretsInContent(content, 'payment.js');

  const stripeFinding = findings.find((f) => f.ruleId === 'stripe-secret-key');
  assert.ok(stripeFinding, 'Expected Stripe secret finding');

  const keyFinding = findings.find((f) => f.ruleId === 'private-key');
  assert.ok(keyFinding, 'Expected Private Key block finding');
});

test('detects Database URLs with passwords', () => {
  const dummyDb = ['postgres://admin:', 'SuperSecretPassword123!', '@db.production.internal:5432/main_db'].join('');
  const content = `DATABASE_URL="${dummyDb}"`;
  const findings = detectSecretsInContent(content, '.env');
  assert.ok(findings.some((f) => f.ruleId === 'database-connection-string'));
});

test('detects Google Cloud API keys', () => {
  const dummyGoogle = ['AIza', 'SyD7K9xQ2mR4vL8tP1wZ6bN0jF3hG5sY8cW'].join('');
  const content = `const googleKey = "${dummyGoogle}";`;
  const findings = detectSecretsInContent(content, 'maps.js');
  const googleFinding = findings.find((f) => f.ruleId === 'google-api-key');
  assert.ok(googleFinding, 'Expected Google Cloud API key to be found');
  assert.equal(googleFinding.provider, 'Google');
  assert.equal(googleFinding.severity, SEVERITY.HIGH);
});

test('detects Slack bot tokens and incoming webhooks', () => {
  const dummySlackBot = ['xoxb', '123456789012', '1234567890123', '9Qz8W2eR4tY6uI1oP3aS5dF7'].join('-');
  const dummyWebhook = ['https:/', 'hooks.slack.com', 'services', 'T01234567', 'B01234567', '9Qz8W2eR4tY6uI1oP3aS5dF7'].join('/');
  const content = `const bot = "${dummySlackBot}";\nconst hook = "${dummyWebhook}";`;
  const findings = detectSecretsInContent(content, 'slack.js');

  assert.ok(findings.some((f) => f.ruleId === 'slack-bot-token'), 'Expected Slack bot token');
  assert.ok(findings.some((f) => f.ruleId === 'slack-webhook'), 'Expected Slack webhook');
});

test('detects Discord bot tokens and webhooks', () => {
  const dummyDiscordBot = ['MTA1MjM0NTY3ODkwMTIzNDU2Nw', 'GF1234', '9Qz8W2eR4tY6uI1oP3aS5dF7gH9jK2l'].join('.');
  const dummyDiscordHook = ['https:/', 'discord.com', 'api', 'webhooks', '123456789012345678', '9Qz8W2eR4tY6uI1oP3aS5dF7gH9jK2lZ4xV6cN8mB0vC2xZ4lK6jH8gF0dSa9Qz8W2eR'].join('/');
  const content = `const token = "${dummyDiscordBot}";\nconst hook = "${dummyDiscordHook}";`;
  const findings = detectSecretsInContent(content, 'discord.js');

  assert.ok(findings.some((f) => f.ruleId === 'discord-bot-token'), 'Expected Discord bot token');
  assert.ok(findings.some((f) => f.ruleId === 'discord-webhook'), 'Expected Discord webhook');
});

test('detects Telegram Bot API tokens', () => {
  const dummyTelegram = ['123456789', 'AAGh9Qz8W2eR4tY6uI1oP3aS5dF7gH9jK2l'].join(':');
  const content = `const botToken = "${dummyTelegram}";`;
  const findings = detectSecretsInContent(content, 'telegram.js');
  const teleFinding = findings.find((f) => f.ruleId === 'telegram-bot-token');
  assert.ok(teleFinding, 'Expected Telegram bot token');
  assert.equal(teleFinding.provider, 'Telegram');
});

test('detects JWT Tokens', () => {
  const dummyJwt = ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0', 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'].join('.');
  const content = `Authorization: Bearer ${dummyJwt}`;
  const findings = detectSecretsInContent(content, 'auth.log');
  const jwtFinding = findings.find((f) => f.ruleId === 'jwt-token');
  assert.ok(jwtFinding, 'Expected JWT token finding');
  assert.equal(jwtFinding.severity, SEVERITY.MEDIUM);
});

test('ignores documentation placeholders and false positives', () => {
  const content = `// Example: sk-proj-your_api_key_here\nconst dummyKey = "AKIA_EXAMPLE_PLACEHOLDER";\nconst templated = "sk-\${OPENAI_API_KEY}";`;
  const findings = detectSecretsInContent(content, 'README.md');
  assert.equal(findings.length, 0, 'Placeholders must be excluded as false positives');
});
