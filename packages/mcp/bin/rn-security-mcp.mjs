#!/usr/bin/env node
/**
 * Entry point for the `rn-security-mcp` server.
 *
 * Wire it into an MCP client, for example:
 *   claude mcp add rn-security -- npx -y @rn-security/mcp
 *
 * The server reads only the directory it is started in (or `--root`), and
 * writes nothing anywhere.
 */
import fs from 'node:fs/promises';
import process from 'node:process';

import { runStdioServer } from '../dist/index.js';

const rootFlag = process.argv.indexOf('--root');
const root = rootFlag === -1 ? process.cwd() : (process.argv[rootFlag + 1] ?? process.cwd());

const manifest = JSON.parse(await fs.readFile(new URL('../package.json', import.meta.url), 'utf8'));

await runStdioServer({ root, version: manifest.version });
