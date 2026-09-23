/**
 * SecretScrub Web Security Playground
 * 100% Client-Side Real-Time Secret Scanner & Shannon Entropy Inspector
 */

// 1. Rules Definition (Exact mirror of src/rules.js for full parity)
export const SEVERITY = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
};

export const RULES = [
  {
    id: 'aws-access-key-id',
    name: 'AWS Access Key ID',
    provider: 'Amazon Web Services',
    severity: SEVERITY.CRITICAL,
    pattern: /\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b/g,
    description: 'Permanent or session credentials for AWS API authentication.',
  },
  {
    id: 'aws-secret-access-key',
    name: 'AWS Secret Access Key',
    provider: 'Amazon Web Services',
    severity: SEVERITY.CRITICAL,
    pattern: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    matchGroup: 1,
    description: 'Secret component of AWS IAM authentication credentials.',
  },
  {
    id: 'github-pat-classic',
    name: 'GitHub Personal Access Token (Classic)',
    provider: 'GitHub',
    severity: SEVERITY.CRITICAL,
    pattern: /\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b/g,
    description: 'Personal access token granting repository/account access.',
  },
  {
    id: 'github-pat-fine-grained',
    name: 'GitHub Fine-Grained Personal Access Token',
    provider: 'GitHub',
    severity: SEVERITY.CRITICAL,
    pattern: /\b(github_pat_[A-Za-z0-9_]{30,120})\b/g,
    description: 'Resource-scoped fine-grained GitHub access token.',
  },
  {
    id: 'openai-api-key',
    name: 'OpenAI API Key',
    provider: 'OpenAI',
    severity: SEVERITY.CRITICAL,
    pattern: /\b(sk-(?:proj-)?[A-Za-z0-9_\-]{32,128})\b/g,
    description: 'Secret API key for OpenAI GPT and embedding endpoints.',
  },
  {
    id: 'anthropic-api-key',
    name: 'Anthropic API Key',
    provider: 'Anthropic',
    severity: SEVERITY.CRITICAL,
    pattern: /\b(sk-ant-[a-zA-Z0-9_\-]{40,128})\b/g,
    description: 'Secret key for Anthropic Claude model invocations.',
  },
  {
    id: 'stripe-secret-key',
    name: 'Stripe Secret Key',
    provider: 'Stripe',
    severity: SEVERITY.CRITICAL,
    pattern: /\b([rs]k_live_[0-9a-zA-Z]{24,99})\b/g,
    description: 'Live Stripe API secret key capable of financial charges.',
  },
  {
    id: 'stripe-publishable-key',
    name: 'Stripe Publishable Key',
    provider: 'Stripe',
    severity: SEVERITY.LOW,
    pattern: /\b(pk_live_[0-9a-zA-Z]{24,99})\b/g,
    description: 'Live publishable key for client-side Stripe integrations.',
  },
  {
    id: 'google-api-key',
    name: 'Google Cloud / Maps API Key',
    provider: 'Google',
    severity: SEVERITY.HIGH,
    pattern: /\b(AIza[0-9A-Za-z\-_]{35})\b/g,
    description: 'Universal Google Cloud / Firebase / Maps API key.',
  },
  {
    id: 'slack-bot-token',
    name: 'Slack Bot / User OAuth Token',
    provider: 'Slack',
    severity: SEVERITY.CRITICAL,
    pattern: /\b(xox[baprs]-[0-9a-zA-Z]{10,48}-[0-9a-zA-Z]{10,48}(?:-[0-9a-zA-Z]{10,48})?)\b/g,
    description: 'Slack application authorization token.',
  },
  {
    id: 'slack-webhook',
    name: 'Slack Incoming Webhook URL',
    provider: 'Slack',
    severity: SEVERITY.HIGH,
    pattern: /\b(https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8,12}\/B[a-zA-Z0-9_]{8,12}\/[a-zA-Z0-9_]{24})\b/g,
    description: 'Slack incoming webhook allowing channel message injection.',
  },
  {
    id: 'discord-bot-token',
    name: 'Discord Bot Token',
    provider: 'Discord',
    severity: SEVERITY.CRITICAL,
    pattern: /\b([MN][A-Za-z\d]{23,26}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38})\b/g,
    description: 'Authentication token for Discord bot operations.',
  },
  {
    id: 'discord-webhook',
    name: 'Discord Webhook URL',
    provider: 'Discord',
    severity: SEVERITY.HIGH,
    pattern: /\b(https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]{17,20}\/[A-Za-z0-9_-]{60,68})\b/g,
    description: 'Direct channel webhook for Discord guild notifications.',
  },
  {
    id: 'telegram-bot-token',
    name: 'Telegram Bot API Token',
    provider: 'Telegram',
    severity: SEVERITY.HIGH,
    pattern: /\b([0-9]{9,10}:[a-zA-Z0-9_-]{35})\b/g,
    description: 'Telegram BotFather generated bot control credential.',
  },
  {
    id: 'private-key',
    name: 'Cryptographic Private Key Block',
    provider: 'PKI / SSH',
    severity: SEVERITY.CRITICAL,
    pattern: /-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY[A-Z ]*-----/g,
    description: 'Asymmetric private key header for servers or code signing.',
  },
  {
    id: 'database-connection-string',
    name: 'Database Connection String with Credentials',
    provider: 'Database',
    severity: SEVERITY.CRITICAL,
    pattern: /\b(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis):\/\/[a-zA-Z0-9_.-]+:(?:(?!\$\{)[^@\s]+)@[a-zA-Z0-9.-]+(?::[0-9]+)?\/[a-zA-Z0-9_.-]*/gi,
    description: 'Full database connection URI containing plaintext passwords.',
  },
  {
    id: 'jwt-token',
    name: 'JSON Web Token (JWT)',
    provider: 'Identity / Auth',
    severity: SEVERITY.MEDIUM,
    pattern: /\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b/g,
    description: 'Base64 encoded signed JSON Web Token containing claims.',
  },
  {
    id: 'generic-hardcoded-secret',
    name: 'Generic High-Entropy Credential Assignment',
    provider: 'Generic',
    severity: SEVERITY.HIGH,
    pattern: /(?:password|passwd|api_key|apikey|secret_key|secretkey|auth_token)\s*[:=]\s*["']([^"'\\s]{12,})["']/gi,
    matchGroup: 1,
    requiresEntropy: true,
    minEntropy: 3.8,
    description: 'High-entropy credential assigned to a sensitive variable name.',
  },
];

// 2. Shannon Entropy Calculation
function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const frequencies = new Map();
  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }
  const length = str.length;
  let entropy = 0;
  for (const count of frequencies.values()) {
    const probability = count / length;
    entropy -= probability * Math.log2(probability);
  }
  return Number(entropy.toFixed(3));
}

// 3. Safe Redaction
function redactSecret(secret, visibleChars = 4) {
  if (!secret) return '';
  const str = String(secret);
  if (str.length <= visibleChars * 2) {
    return '•'.repeat(str.length);
  }
  const prefix = str.slice(0, visibleChars);
  const suffix = str.slice(-visibleChars);
  const hiddenCount = Math.min(16, str.length - visibleChars * 2);
  return `${prefix}${'•'.repeat(hiddenCount)}${suffix}`;
}

// Obvious False Positive check
function isFalsePositive(matched, line) {
  const lower = matched.toLowerCase();
  const lowerLine = line.toLowerCase();
  const placeholders = ['placeholder', 'example', 'your_api_key', 'your-token', 'dummy', 'fake', '<your', '${'];
  return placeholders.some(p => lower.includes(p) || lowerLine.includes(p));
}

// DOM Elements
const codeInput = document.getElementById('codeInput');
const charCount = document.getElementById('charCount');
const entropyToggle = document.getElementById('entropyToggle');
const findingsBadge = document.getElementById('findingsBadge');
const statusCard = document.getElementById('statusCard');
const statusIcon = document.getElementById('statusIcon');
const statusHeading = document.getElementById('statusHeading');
const statusDesc = document.getElementById('statusDesc');
const findingsList = document.getElementById('findingsList');
const panelActions = document.getElementById('panelActions');
const sanitizeBtn = document.getElementById('sanitizeBtn');
const downloadSanitizedBtn = document.getElementById('downloadSanitizedBtn');
const exportJsonBtn = document.getElementById('exportJsonBtn');
const clearBtn = document.getElementById('clearBtn');
const filePicker = document.getElementById('filePicker');
const dropOverlay = document.getElementById('dropOverlay');

// Sample Buttons
const sampleEnvBtn = document.getElementById('sampleEnvBtn');
const sampleKeysBtn = document.getElementById('sampleKeysBtn');
const sampleCleanBtn = document.getElementById('sampleCleanBtn');

// Filter & Modal Elements
const filterGroup = document.getElementById('filterGroup');
const openRulesBtn = document.getElementById('openRulesBtn');
const closeRulesModal = document.getElementById('closeRulesModal');
const rulesModal = document.getElementById('rulesModal');
const rulesModalList = document.getElementById('rulesModalList');
const rulesSearchInput = document.getElementById('rulesSearchInput');

let currentFindings = [];
let activeSeverityFilter = 'all';
const unmaskedIds = new Set();

// Scan Function
function runScan() {
  const content = codeInput.value;
  const enableEntropy = entropyToggle.checked;
  const lines = content.split(/\r?\n/);

  charCount.textContent = `${lines.length} lines • ${content.length} chars`;

  if (!content.trim()) {
    currentFindings = [];
    unmaskedIds.clear();
    renderCleanState('No Content to Inspect', 'Paste credentials or configuration code above to evaluate patterns in real-time.');
    return;
  }

  const findings = [];
  let findingCounter = 0;

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex];
    const lineNumber = lineIndex + 1;

    if (!line || line.length > 5000) continue;

    // Test Rule Signatures
    for (const rule of RULES) {
      const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
      let match;

      while ((match = regex.exec(line)) !== null) {
        const fullMatch = match[0];
        const secretCandidate = rule.matchGroup ? match[rule.matchGroup] : fullMatch;

        if (!secretCandidate || isFalsePositive(secretCandidate, line)) continue;

        const entropy = calculateShannonEntropy(secretCandidate);
        if (rule.requiresEntropy && rule.minEntropy && entropy < rule.minEntropy) {
          continue;
        }

        findingCounter++;
        findings.push({
          id: `finding-${findingCounter}`,
          ruleId: rule.id,
          ruleName: rule.name,
          provider: rule.provider,
          severity: rule.severity,
          lineNumber,
          column: match.index + 1,
          rawSecret: secretCandidate,
          maskedSecret: redactSecret(secretCandidate),
          lineSnippet: line.trim(),
          entropy,
        });
      }
    }

    // Generic High-Entropy Scan
    if (enableEntropy) {
      const tokens = line.matchAll(/\b([A-Za-z0-9+/=_-]{20,80})\b/g);
      for (const tokenMatch of tokens) {
        const token = tokenMatch[1];
        if (isFalsePositive(token, line)) continue;

        // Skip tokens already detected by rules
        if (findings.some(f => f.lineNumber === lineNumber && f.rawSecret === token)) continue;

        const entropy = calculateShannonEntropy(token);
        if (entropy >= 4.2) {
          findingCounter++;
          findings.push({
            id: `finding-${findingCounter}`,
            ruleId: 'generic-high-entropy',
            ruleName: 'Unstructured High-Entropy Token',
            provider: 'Heuristic Randomness',
            severity: SEVERITY.HIGH,
            lineNumber,
            column: tokenMatch.index + 1,
            rawSecret: token,
            maskedSecret: redactSecret(token),
            lineSnippet: line.trim(),
            entropy,
          });
        }
      }
    }
  }

  currentFindings = findings;
  renderFindings(findings);
}

function renderCleanState(heading, desc) {
  findingsBadge.textContent = 'Clean';
  findingsBadge.className = 'findings-badge badge-clean';
  statusCard.className = 'status-card';
  statusIcon.textContent = '🛡️';
  statusHeading.textContent = heading;
  statusDesc.textContent = desc;
  findingsList.innerHTML = '';
  panelActions.classList.add('hidden');
}

function renderFindings(findings) {
  if (findings.length === 0) {
    renderCleanState('0 Secrets Detected (Clean)', 'All lines evaluated against 18+ high-fidelity patterns & Shannon entropy without any flags.');
    return;
  }

  findingsBadge.textContent = `${findings.length} Leaks`;
  findingsBadge.className = 'findings-badge badge-danger';
  statusCard.className = 'status-card danger';
  statusIcon.textContent = '🚨';
  statusHeading.textContent = `Security Alert: ${findings.length} Secrets Detected!`;
  statusDesc.textContent = 'Identified high-risk credentials or cryptographic keys that must not be committed to Git.';
  panelActions.classList.remove('hidden');

  applyFindingsFilter();
}

function applyFindingsFilter() {
  const filtered = activeSeverityFilter === 'all'
    ? currentFindings
    : currentFindings.filter(f => f.severity.toLowerCase() === activeSeverityFilter.toLowerCase());

  findingsList.innerHTML = '';

  if (filtered.length === 0) {
    const emptyNotice = document.createElement('div');
    emptyNotice.className = 'empty-filter-notice';
    emptyNotice.textContent = `No findings matching filter "${activeSeverityFilter}".`;
    findingsList.appendChild(emptyNotice);
    return;
  }

  filtered.forEach(f => {
    const card = document.createElement('div');
    card.className = `finding-card severity-${f.severity}`;

    const isUnmasked = unmaskedIds.has(f.id);
    const displaySecret = isUnmasked ? f.rawSecret : f.maskedSecret;

    const safeSnippet = escapeHtml(f.lineSnippet);
    const safeRaw = escapeHtml(f.rawSecret);
    const highlightedSnippet = safeSnippet.replace(
      safeRaw,
      `<span class="finding-masked ${isUnmasked ? 'unmasked-reveal' : ''}">${escapeHtml(displaySecret)}</span>`
    );

    card.innerHTML = `
      <div class="finding-header">
        <span class="finding-rule-name">${escapeHtml(f.ruleName)}</span>
        <div class="finding-badges">
          <button type="button" class="unmask-toggle-btn" data-id="${f.id}" title="${isUnmasked ? 'Mask secret' : 'Reveal secret'}">
            ${isUnmasked ? '🙈 Mask' : '👁️ Reveal'}
          </button>
          <span class="sev-badge sev-${f.severity}">${f.severity}</span>
          <span class="entropy-badge">H(X): ${f.entropy}</span>
        </div>
      </div>
      <div class="finding-location">Provider: <strong>${escapeHtml(f.provider)}</strong> • Line ${f.lineNumber}, Col ${f.column}</div>
      <div class="finding-snippet">${highlightedSnippet}</div>
    `;

    findingsList.appendChild(card);
  });

  // Attach unmask handlers
  findingsList.querySelectorAll('.unmask-toggle-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const id = e.currentTarget.getAttribute('data-id');
      if (unmaskedIds.has(id)) {
        unmaskedIds.delete(id);
      } else {
        unmaskedIds.add(id);
      }
      applyFindingsFilter();
    });
  });
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function getSanitizedContent() {
  let content = codeInput.value;
  if (!content) return '';
  currentFindings.forEach(f => {
    content = content.replaceAll(f.rawSecret, f.maskedSecret);
  });
  return content;
}

// Sanitize & Copy Redacted Code
sanitizeBtn.addEventListener('click', () => {
  const content = getSanitizedContent();
  if (!content) return;

  navigator.clipboard.writeText(content).then(() => {
    const originalText = sanitizeBtn.textContent;
    sanitizeBtn.textContent = '✔ Copied Sanitized Code!';
    setTimeout(() => {
      sanitizeBtn.textContent = originalText;
    }, 2000);
  });
});

// Download Sanitized File
downloadSanitizedBtn.addEventListener('click', () => {
  const content = getSanitizedContent();
  if (!content) return;

  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'sanitized-file.txt';
  a.click();
  URL.revokeObjectURL(url);
});

// Export JSON
exportJsonBtn.addEventListener('click', () => {
  const data = JSON.stringify({
    timestamp: new Date().toISOString(),
    totalLeaks: currentFindings.length,
    findings: currentFindings.map(({ id, ...rest }) => rest),
  }, null, 2);

  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'secret-scrub-report.json';
  a.click();
  URL.revokeObjectURL(url);
});

// Severity Filter Tabs
filterGroup.addEventListener('click', (e) => {
  const chip = e.target.closest('.filter-chip');
  if (!chip) return;
  filterGroup.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
  chip.classList.add('active');
  activeSeverityFilter = chip.getAttribute('data-filter') || 'all';
  applyFindingsFilter();
});

// File Picker
filePicker.addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (file) {
    const reader = new FileReader();
    reader.onload = (event) => {
      codeInput.value = event.target.result;
      runScan();
    };
    reader.readAsText(file);
  }
});

// Event Listeners
codeInput.addEventListener('input', runScan);
entropyToggle.addEventListener('change', runScan);

clearBtn.addEventListener('click', () => {
  codeInput.value = '';
  filePicker.value = '';
  runScan();
});

// Sample 1: Leaked .env (Constructed via parts so scanner self-scan passes cleanly)
sampleEnvBtn.addEventListener('click', () => {
  const oaiPart = ['sk', 'proj', 'abc1234567890abcdef1234567890abcdef1234567890'].join('-');
  const awsPart = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
  const awsSecPart = ['wJalrXUtnFEMI/K7MDENG/bPxRfiCY', 'EXAMPLEKEY'].join('');
  const dbPart = ['postgres://app_admin:P@ssw0rd998877!', '@prod-db.example.com:5432/core'].join('');

  codeInput.value = `# Production Credentials - DO NOT SHARE
PORT=3000
ENVIRONMENT=production

# Amazon Web Services
AWS_ACCESS_KEY_ID=${awsPart}
AWS_SECRET_ACCESS_KEY=${awsSecPart}

# OpenAI API Key
OPENAI_API_KEY=${oaiPart}

# Database Connection
DATABASE_URL=${dbPart}
`;
  runScan();
});

// Sample 2: Stripe & GitHub Keys & Chat Webhooks
sampleKeysBtn.addEventListener('click', () => {
  const stripeDummy = ['sk', 'live', '51Abcdef1234567890ABCDEF1234567890'].join('_');
  const slackDummy = ['https:/', 'hooks.slack.com', 'services', 'T00000000', 'B00000000', 'XXXXXXXXXXXXXXXXXXXXXXXX'].join('/');
  const ghpDummy = ['ghp', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'].join('_');
  const anthropicDummy = ['sk', 'ant', 'api03-abcdefghijklmnopqrstuvwxyz01234567890'].join('-');
  const discordDummy = ['https:/', 'discord.com', 'api', 'webhooks', '123456789012345678', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678901234567'].join('/');

  codeInput.value = `// Payment, Chat & CI/CD Integrations
export const config = {
  githubToken: "${ghpDummy}",
  stripeLiveKey: "${stripeDummy}",
  anthropicKey: "${anthropicDummy}",
  slackWebhook: "${slackDummy}",
  discordWebhook: "${discordDummy}"
};
`;
  runScan();
});

// Sample 3: Clean Config
sampleCleanBtn.addEventListener('click', () => {
  codeInput.value = `{
  "name": "enterprise-microservice",
  "version": "2.4.0",
  "description": "Standard service configuration with no credentials",
  "logging": {
    "level": "info",
    "format": "json"
  },
  "cacheTtlSeconds": 3600
}
`;
  runScan();
});

// Drag and drop file onto editor
['dragenter', 'dragover'].forEach(name => {
  codeInput.addEventListener(name, (e) => {
    e.preventDefault();
    dropOverlay.classList.remove('hidden');
  });
});

['dragleave', 'drop'].forEach(name => {
  dropOverlay.addEventListener(name, (e) => {
    e.preventDefault();
    dropOverlay.classList.add('hidden');
  });
});

dropOverlay.addEventListener('drop', (e) => {
  const file = e.dataTransfer.files[0];
  if (file) {
    const reader = new FileReader();
    reader.onload = (event) => {
      codeInput.value = event.target.result;
      runScan();
    };
    reader.readAsText(file);
  }
});

// Signatures Modal Logic
function renderRulesModal(filterQuery = '') {
  const q = filterQuery.toLowerCase().trim();
  const filteredRules = q
    ? RULES.filter(r => r.name.toLowerCase().includes(q) || r.provider.toLowerCase().includes(q) || r.id.toLowerCase().includes(q) || r.description.toLowerCase().includes(q))
    : RULES;

  rulesModalList.innerHTML = '';

  if (filteredRules.length === 0) {
    rulesModalList.innerHTML = '<div class="empty-filter-notice">No signatures match your search query.</div>';
    return;
  }

  filteredRules.forEach(rule => {
    const item = document.createElement('div');
    item.className = 'rule-item-card';
    item.innerHTML = `
      <div class="rule-item-header">
        <div>
          <span class="rule-item-title">${escapeHtml(rule.name)}</span>
          <span class="rule-item-id">${escapeHtml(rule.id)}</span>
        </div>
        <div class="rule-item-meta">
          <span class="sev-badge sev-${rule.severity}">${rule.severity}</span>
          <span class="rule-provider-badge">${escapeHtml(rule.provider)}</span>
        </div>
      </div>
      <p class="rule-item-desc">${escapeHtml(rule.description)}</p>
    `;
    rulesModalList.appendChild(item);
  });
}

openRulesBtn.addEventListener('click', () => {
  rulesModal.classList.remove('hidden');
  renderRulesModal(rulesSearchInput.value);
  rulesSearchInput.focus();
});

closeRulesModal.addEventListener('click', () => {
  rulesModal.classList.add('hidden');
});

rulesModal.addEventListener('click', (e) => {
  if (e.target === rulesModal) {
    rulesModal.classList.add('hidden');
  }
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !rulesModal.classList.contains('hidden')) {
    rulesModal.classList.add('hidden');
  }
});

rulesSearchInput.addEventListener('input', () => {
  renderRulesModal(rulesSearchInput.value);
});

// Initial scan
runScan();

// Auto-trigger for URL query parameters (e.g. for demos/screenshots)
const params = new URLSearchParams(window.location.search);
if (params.has('demo')) {
  setTimeout(() => sampleKeysBtn?.click(), 100);
}
