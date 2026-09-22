#!/usr/bin/env node

import { createCli } from '../src/cli.js';
import { startWebServer } from '../src/server.js';

const args = process.argv.slice(2);
const webIdx = args.findIndex((a) => a === '--web' || a.startsWith('--web='));

if (webIdx !== -1) {
  let port = 3000;
  const webVal = args[webIdx];
  if (webVal.includes('=')) {
    port = parseInt(webVal.split('=')[1], 10) || 3000;
  } else if (args[webIdx + 1] && /^\d+$/.test(args[webIdx + 1])) {
    port = parseInt(args[webIdx + 1], 10);
  }
  await startWebServer({ port });
} else {
  const cli = createCli();
  cli.parse(process.argv);
}
