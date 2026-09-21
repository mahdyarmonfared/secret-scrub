#!/usr/bin/env node

import { createCli } from '../src/cli.js';

const cli = createCli();
cli.parse(process.argv);
