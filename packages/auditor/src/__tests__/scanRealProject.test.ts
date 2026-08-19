import fs from 'node:fs';
import path from 'node:path';

import { auditProject } from '../engine/auditProject.js';
import { defaultConfig } from '../config/defaults.js';
import type { RawFinding } from '../types/finding.js';
import type { RuleContext, SecurityRule } from '../types/rule.js';

/**
 * Scanning a real React Native application, inside a budget.
 *
 * Synthetic fixtures cannot tell you whether a scanner is usable. This one runs
 * over the example app in this repository — a real project with an Android
 * source tree, an iOS source tree, generated build output and a `node_modules`
 * directory — and asserts that the scan stays inside its time and memory
 * budget while still reaching the application's own code.
 */

// Jest runs with this package as its root directory, so the workspace is two
// levels up. Resolved rather than hardcoded so the test survives a move.
const repositoryRoot = path.resolve(process.cwd(), '../..');
const exampleApp = path.join(repositoryRoot, 'example');

/** Counts what it sees, so the test can assert coverage rather than findings. */
function countingRule(seen: Set<string>): SecurityRule {
  return {
    id: 'RNSEC-COVERAGE-001',
    name: 'Coverage probe',
    description: 'Records which files the engine handed to a rule.',
    severity: 'info',
    categories: ['configuration'],
    languages: [],
    fileKinds: [],
    knowledge: {},
    detect: (context: RuleContext): RawFinding[] => {
      seen.add(context.file.path);
      return [];
    },
  };
}

const describeIfPresent = fs.existsSync(exampleApp) ? describe : describe.skip;

describeIfPresent('scanning the example application', () => {
  it('covers the application source without walking dependencies or build output', async () => {
    const seen = new Set<string>();
    const startedAt = Date.now();

    const report = await auditProject({
      root: exampleApp,
      rules: [countingRule(seen)],
      config: { ...defaultConfig(), limits: { ...defaultConfig().limits, timeoutMs: 60_000 } },
    });

    const elapsed = Date.now() - startedAt;

    // The application's own entry point is reached.
    expect([...seen].some((file) => file.endsWith('src/App.tsx'))).toBe(true);

    // Dependencies, pods and build output are not.
    expect([...seen].some((file) => file.includes('node_modules/'))).toBe(false);
    expect([...seen].some((file) => file.includes('ios/Pods/'))).toBe(false);
    expect([...seen].some((file) => file.includes('/build/'))).toBe(false);

    expect(report.timedOut).toBe(false);
    expect(report.ruleErrors).toHaveLength(0);
    // A generous ceiling: the assertion is that the scan is bounded, not a
    // benchmark that fails on a loaded CI machine.
    expect(elapsed).toBeLessThan(60_000);
    // Reading a whole project must not mean holding it all at once.
    expect(report.stats.bytesRead).toBeLessThan(defaultConfig().limits.maxTotalBytes);
  }, 120_000);

  it('parses the TypeScript and TSX it finds', async () => {
    const report = await auditProject({
      root: exampleApp,
      rules: [countingRule(new Set())],
      config: { ...defaultConfig(), include: ['src/**'] },
    });

    expect(report.stats.filesParsed).toBeGreaterThan(0);
    expect(report.stats.filesAnalysed).toBe(report.stats.filesDiscovered);
  }, 120_000);
});
