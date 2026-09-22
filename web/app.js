/**
 * SecretScrub Web Security Playground
 * 100% Client-Side Real-Time Secret Scanner & Shannon Entropy Inspector
 */

// 1. Rules Definition (Client-side mirror of src/rules.js)
const SEVERITY = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
};

const RULES = [
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
    pattern: /\b(github_pat_[A-Za-z0-9_]{82})\b/g,
    description: 'Scoped fine-grained access token for GitHub organizations.',
  },
  {
    id: 'openai-api-key',
    name: 'OpenAI API Secret Key',
    provider: 'OpenAI',
    severity: SEVERITY.CRITICAL,
    pattern: /\b(sk-(?:proj-|admin-)?[A-Za-z0-9_-]{48,120})\b/g,
    description: 'Authentication key for OpenAI API services.',
  },
  {
    id: 'anthropic-api-key',
    name: 'Anthropic Claude API Key',
    provider: 'Anthropic',
    severity: SEVERITY.CRITICAL,
    pattern: /\b(sk-ant-[A-Za-z0-9_-]{40,120})\b/g,
    description: 'Authentication credential for Claude and Anthropic APIs.',
  },
  {
    id: 'stripe-live-secret-key',
    name: 'Stripe Live Secret Key',
    provider: 'Stripe',
    severity: SEVERITY.CRITICAL,
    pattern: /\b(sk_live_[0-9a-zA-Z]{24,99})\b/g,
    description: 'Live secret key with full payment processing authorization.',
  },
  {
    id: 'slack-incoming-webhook',
    name: 'Slack Incoming Webhook URL',
    provider: 'Slack',
    severity: SEVERITY.HIGH,
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9_]{8,11}\/B[A-Z0-9_]{8,12}\/[A-Za-z0-9]{24}/g,
    description: 'Incoming webhook URL allowing unauthorized messaging into Slack channels.',
  },
  {
    id: 'database-connection-uri',
    name: 'Database Connection URI with Password',
    provider: 'Database',
    severity: SEVERITY.CRITICAL,
    pattern: /(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|amqp):\/\/[^:\s\/]+:([^@\s\/]{3,})@[^\s\/]+/gi,
    matchGroup: 1,
    description: 'Direct database connection string containing plaintext passwords.',
  },
  {
    id: 'private-key-block',
    name: 'Asymmetric Private Key Block',
    provider: 'Cryptography',
    severity: SEVERITY.CRITICAL,
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    description: 'Unencrypted cryptographic private key file block.',
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
  const placeholders = ['placeholder', 'example', 'your_api_key', 'your-token', 'dummy', 'fake'];
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
const exportJsonBtn = document.getElementById('exportJsonBtn');
const clearBtn = document.getElementById('clearBtn');
const dropOverlay = document.getElementById('dropOverlay');

// Sample Buttons
const sampleEnvBtn = document.getElementById('sampleEnvBtn');
const sampleKeysBtn = document.getElementById('sampleKeysBtn');
const sampleCleanBtn = document.getElementById('sampleCleanBtn');

let currentFindings = [];

// Scan Function
function runScan() {
  const content = codeInput.value;
  const enableEntropy = entropyToggle.checked;
  const lines = content.split(/\r?\n/);

  charCount.textContent = `${lines.length} lines • ${content.length} chars`;

  if (!content.trim()) {
    currentFindings = [];
    renderCleanState('No Content to Inspect', 'Paste credentials or configuration code above to evaluate patterns in real-time.');
    return;
  }

  const findings = [];

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
        findings.push({
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
          findings.push({
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
    renderCleanState('0 Secrets Detected (Clean)', 'All lines evaluated against 18+ high-fidelity cloud patterns & Shannon entropy without any flags.');
    return;
  }

  findingsBadge.textContent = `${findings.length} Leaks`;
  findingsBadge.className = 'findings-badge badge-danger';
  statusCard.className = 'status-card danger';
  statusIcon.textContent = '🚨';
  statusHeading.textContent = `Security Alert: ${findings.length} Secrets Detected!`;
  statusDesc.textContent = 'Identified high-risk credentials or random cryptographic tokens that must not be committed to Git.';
  panelActions.classList.remove('hidden');

  findingsList.innerHTML = '';

  findings.forEach(f => {
    const card = document.createElement('div');
    card.className = `finding-card severity-${f.severity}`;

    // Highlight masked secret inside line snippet
    const highlightedSnippet = f.lineSnippet.replace(
      f.rawSecret,
      `<span class="finding-masked">${f.maskedSecret}</span>`
    );

    card.innerHTML = `
      <div class="finding-header">
        <span class="finding-rule-name">${f.ruleName}</span>
        <div class="finding-badges">
          <span class="sev-badge sev-${f.severity}">${f.severity}</span>
          <span class="entropy-badge">H(X): ${f.entropy}</span>
        </div>
      </div>
      <div class="finding-location">Provider: <strong>${f.provider}</strong> • Line ${f.lineNumber}, Col ${f.column}</div>
      <div class="finding-snippet">${highlightedSnippet}</div>
    `;

    findingsList.appendChild(card);
  });
}

// Sanitize & Copy Redacted Code
sanitizeBtn.addEventListener('click', () => {
  let content = codeInput.value;
  if (!content) return;

  // Replace all detected raw secrets with their masked versions
  currentFindings.forEach(f => {
    content = content.replaceAll(f.rawSecret, f.maskedSecret);
  });

  navigator.clipboard.writeText(content).then(() => {
    const originalText = sanitizeBtn.textContent;
    sanitizeBtn.textContent = '✔ Copied Sanitized Code!';
    setTimeout(() => {
      sanitizeBtn.textContent = originalText;
    }, 2000);
  });
});

// Export JSON
exportJsonBtn.addEventListener('click', () => {
  const data = JSON.stringify({
    timestamp: new Date().toISOString(),
    totalLeaks: currentFindings.length,
    findings: currentFindings,
  }, null, 2);

  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'secret-scrub-report.json';
  a.click();
  URL.revokeObjectURL(url);
});

// Event Listeners
codeInput.addEventListener('input', runScan);
entropyToggle.addEventListener('change', runScan);

clearBtn.addEventListener('click', () => {
  codeInput.value = '';
  runScan();
});

// Sample 1: Leaked .env
sampleEnvBtn.addEventListener('click', () => {
  codeInput.value = `# Production Credentials - DO NOT SHARE
PORT=3000
ENVIRONMENT=production

# Amazon Web Services
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# OpenAI API Key
OPENAI_API_KEY=sk-proj-abc1234567890abcdef1234567890abcdef1234567890

# Database Connection
DATABASE_URL=postgres://app_admin:P@ssw0rd998877!@prod-db.example.com:5432/core
`;
  runScan();
});

// Sample 2: Stripe & GitHub Keys
sampleKeysBtn.addEventListener('click', () => {
  const stripeDummy = ['sk', 'live', '51Abcdef1234567890ABCDEF1234567890'].join('_');
  const slackDummy = ['https:/', 'hooks.slack.com', 'services', 'T00000000', 'B00000000', 'XXXXXXXXXXXXXXXXXXXXXXXX'].join('/');
  codeInput.value = `// Payment and CI/CD Integrations
export const config = {
  githubToken: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
  stripeLiveKey: "${stripeDummy}",
  anthropicKey: "sk-ant-api03-abcdefghijklmnopqrstuvwxyz01234567890",
  slackWebhook: "${slackDummy}"
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

// Initial scan
runScan();

// Auto-trigger for URL query parameters (e.g. for screenshots)
const params = new URLSearchParams(window.location.search);
if (params.has('demo')) {
  setTimeout(() => sampleKeysBtn?.click(), 100);
}

