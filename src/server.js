import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import chalk from 'chalk';
import { RULES } from './rules.js';
import { detectSecretsInContent } from './detector.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const WEB_DIR = path.resolve(__dirname, '../web');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

/**
 * Start the built-in SecretScrub Web Playground server.
 * @param {object} [options={}]
 * @param {number} [options.port=3004] - Server listening port
 * @returns {Promise<http.Server>}
 */
export function startWebServer(options = {}) {
  const port = options.port || 3004;

  const server = http.createServer(async (req, res) => {
    try {
      const pathname = req.url.split('?')[0];

      // API Endpoint: GET /api/rules
      if (req.method === 'GET' && pathname === '/api/rules') {
        const serializedRules = RULES.map((r) => ({
          id: r.id,
          name: r.name,
          provider: r.provider,
          severity: r.severity,
          description: r.description,
        }));
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ rules: serializedRules, total: serializedRules.length }));
        return;
      }

      // API Endpoint: POST /api/scan
      if (req.method === 'POST' && pathname === '/api/scan') {
        let body = '';
        req.on('data', (chunk) => {
          body += chunk;
          if (body.length > 5 * 1024 * 1024) {
            req.destroy();
          }
        });
        req.on('end', () => {
          try {
            const parsed = JSON.parse(body || '{}');
            const content = parsed.content || '';
            const enableEntropy = Boolean(parsed.enableEntropy);
            const findings = detectSecretsInContent(content, 'api-request', { enableEntropy });
            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({
              timestamp: new Date().toISOString(),
              totalLeaks: findings.length,
              findings,
            }));
          } catch {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid JSON request body' }));
          }
        });
        return;
      }

      // Static file serving
      const urlPath = (pathname === '/' || pathname === '') ? '/index.html' : pathname;
      const filePath = path.join(WEB_DIR, urlPath);

      // Prevent directory traversal
      if (!filePath.startsWith(WEB_DIR)) {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('403 Forbidden');
        return;
      }

      const fileContent = await fs.readFile(filePath);
      const ext = path.extname(filePath).toLowerCase();
      const contentType = MIME_TYPES[ext] || 'application/octet-stream';

      res.writeHead(200, { 'Content-Type': contentType });
      res.end(fileContent);
    } catch {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('404 Not Found');
    }
  });

  return new Promise((resolve, reject) => {
    server.listen(port, () => {
      console.log('');
      console.log(chalk.hex('#F43F5E').bold('🛡️  SecretScrub Web Security Playground is live!'));
      console.log(`  🌐 Local:   ${chalk.green.bold(`http://localhost:${port}`)}`);
      console.log(`  🔒 Privacy: ${chalk.white('100% Client-Side / Zero Data Transmitted')}`);
      console.log(`  🛑 Stop:    ${chalk.gray('Press Ctrl+C to shutdown')}`);
      console.log('');
      resolve(server);
    });

    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.log(chalk.yellow(`Port ${port} in use, trying ${port + 1}...`));
        resolve(startWebServer({ ...options, port: port + 1 }));
      } else {
        reject(err);
      }
    });
  });
}
