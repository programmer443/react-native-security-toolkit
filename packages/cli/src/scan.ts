import fs from 'node:fs/promises';

import {
  AuditorConfigError,
  auditProject,
  builtinRules,
  getReporter,
  loadConfig,
} from '@rn-security/auditor';
import type { AuditReport, SecurityRule } from '@rn-security/auditor';

import { CliError, ExitCode } from './context.js';
import type { CliContext, ExitCodeValue } from './context.js';
import type { ScanOptions } from './options.js';

/**
 * The scan-and-report pipeline every scanning command shares.
 *
 * `audit`, `secrets` and `dependencies` differ only in **which rules run** and
 * what they say when they find nothing. Keeping the rest here means the three
 * cannot drift in how they resolve configuration, honour `--fail-on`, or decide
 * an exit code — which is exactly the kind of divergence that makes a CLI
 * untrustworthy in CI.
 */

export interface ScanCommand {
  readonly rules: readonly SecurityRule[];
  /** Printed after a scan that produced nothing, to say what was actually checked. */
  readonly emptyNote?: string;
}

export async function runScan(
  options: ScanOptions,
  command: ScanCommand,
  context: CliContext,
  toolVersion: string
): Promise<ExitCodeValue> {
  await assertDirectory(options.target);

  if (command.rules.length === 0) {
    throw new CliError('No rules matched this command, so there was nothing to run.');
  }

  // A malformed configuration file is the user's to fix, so it exits 2 like any
  // other usage error. Letting it reach the generic handler would report a
  // project's typo as a bug in the tool — and a CI pipeline that cannot tell a
  // broken config from a clean scan will eventually treat one as the other.
  let config;
  try {
    ({ config } = await loadConfig(options.target, options.config));
  } catch (error: unknown) {
    if (error instanceof AuditorConfigError) {
      throw new CliError(error.message);
    }
    throw error;
  }

  const report = await auditProject({
    root: options.target,
    rules: [...command.rules],
    config: {
      ...config,
      ...(options.minimum === undefined ? {} : { minimumSeverity: options.minimum }),
      ...(options.failOn === undefined ? {} : { failOn: options.failOn }),
    },
  });

  const reporter = getReporter(options.format);
  const output = reporter.render(report, {
    toolVersion,
    includeRoot: options.includeRoot,
    colour: options.colour,
  });

  if (options.out === undefined) {
    context.stdout(output);
  } else {
    await writeOutput(options.out, output);
    context.stdout(
      `Wrote ${report.findings.length} finding(s) to ${options.out} as ${reporter.name}.\n`
    );
  }

  if (
    report.findings.length === 0 &&
    command.emptyNote !== undefined &&
    options.format === 'console'
  ) {
    context.stdout(`${command.emptyNote}\n`);
  }

  return exitCodeFor(report);
}

/**
 * Findings at or above the threshold are the only thing that fails a scan.
 *
 * Not rule errors, and not an incomplete scan: both are reported loudly in the
 * output, but neither is a finding, and conflating them would make a flaky
 * timeout look like a vulnerability.
 */
export function exitCodeFor(report: AuditReport): ExitCodeValue {
  return report.exceedsFailOn ? ExitCode.FindingsAtOrAboveThreshold : ExitCode.Ok;
}

/** Rules whose categories intersect the given set. */
export function rulesInCategories(categories: readonly string[]): readonly SecurityRule[] {
  return builtinRules.filter((rule) =>
    rule.categories.some((category) => categories.includes(category))
  );
}

async function assertDirectory(target: string): Promise<void> {
  try {
    const stats = await fs.stat(target);
    if (!stats.isDirectory()) {
      throw new CliError(`${target} is not a directory.`);
    }
  } catch (error: unknown) {
    if (error instanceof CliError) {
      throw error;
    }
    throw new CliError(
      `Cannot read ${target}: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

async function writeOutput(destination: string, contents: string): Promise<void> {
  try {
    await fs.writeFile(destination, contents, 'utf8');
  } catch (error: unknown) {
    throw new CliError(
      `Could not write ${destination}: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}
