#!/usr/bin/env node
/**
 * Entry point for the `rn-security` command.
 *
 * Deliberately thin: it resolves the compiled CLI and hands over. Keeping logic
 * out of the bin shim is what lets the whole CLI be tested in-process, without
 * spawning a shell.
 */
import fs from 'node:fs/promises';
import process from 'node:process';

import { run } from '../dist/main.js';

// Read from the manifest rather than a constant in the source: a hardcoded
// version drifts the moment a release bumps package.json, and it is reported in
// every JSON and SARIF file this CLI writes.
const manifest = JSON.parse(await fs.readFile(new URL('../package.json', import.meta.url), 'utf8'));

const exitCode = await run(
  process.argv.slice(2),
  {
    cwd: process.cwd(),
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text),
    isTty: process.stdout.isTTY === true,
  },
  { version: manifest.version }
);

process.exitCode = exitCode;
