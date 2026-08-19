import path from 'node:path';

import { analyseRuntimeReadiness } from '@rn-security/auditor';
import type { RuntimeReadiness } from '@rn-security/auditor';

import { CliError, ExitCode } from '../context.js';
import { parseSafely } from '../options.js';
import type { CliContext, ExitCodeValue } from '../context.js';

/**
 * `rn-security runtime` — is this project set up so the runtime checks can work?
 *
 * **It does not run a security check.** Root detection, jailbreak detection and
 * the rest execute inside the application, on a device; a command-line tool on a
 * developer's laptop cannot perform them, and a command that pretended to would
 * be exactly the fabricated capability the brief forbids.
 *
 * The analysis lives in the auditor — it is static analysis of a project's own
 * configuration, and the MCP server needs the same answers. This command only
 * decides how to print them.
 */
export async function runtimeCommand(
  argv: readonly string[],
  context: CliContext
): Promise<ExitCodeValue> {
  const { values, positionals } = parseSafely(argv, { format: { type: 'string' } });

  const format = (values['format'] as string | undefined) ?? 'console';
  if (format !== 'console' && format !== 'json') {
    throw new CliError(`--format must be console or json for this command. Received "${format}".`);
  }

  const target = path.resolve(context.cwd, positionals[0] ?? '.');
  const checks: readonly RuntimeReadiness[] = await analyseRuntimeReadiness(target);

  if (format === 'json') {
    context.stdout(`${JSON.stringify({ target, checks }, null, 2)}\n`);
    return ExitCode.Ok;
  }

  const lines: string[] = [
    'Runtime readiness — project configuration only.',
    '',
    'These checks look at what the project declares. The runtime security checks',
    'themselves execute inside the application on a device; nothing here can run',
    'them, and nothing here reports on a device.',
    '',
  ];

  for (const check of checks) {
    const marker = check.state === 'ready' ? 'ok  ' : check.state === 'missing' ? 'MISS' : '--  ';
    lines.push(`${marker} [${check.platform}] ${check.item}`, `       ${check.detail}`);
  }

  const missing = checks.filter((check) => check.state === 'missing').length;
  lines.push(
    '',
    missing === 0
      ? 'Nothing missing. Runtime checks that depend on project configuration can reach a verdict.'
      : `${missing} item(s) missing. The signals that depend on them will report "unknown" rather ` +
          'than a verdict — which is honest, but not useful.',
    '',
    'See docs/runtime/ for what each check detects and how to interpret it.'
  );

  context.stdout(`${lines.join('\n')}\n`);

  // Missing configuration is advice, not a failure: a project may deliberately
  // not use the checks that need it.
  return ExitCode.Ok;
}
