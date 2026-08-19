import fs from 'node:fs/promises';
import path from 'node:path';

import { getReporter } from '@rn-security/auditor';
import type { AuditReport } from '@rn-security/auditor';

import { CliError, ExitCode } from '../context.js';
import { parseSafely } from '../options.js';
import type { CliContext, ExitCodeValue } from '../context.js';

/**
 * `rn-security report` — re-render a JSON report in another format.
 *
 * Scan once, publish several ways. A CI job that produced SARIF for code
 * scanning and then re-ran the scan to produce a Markdown comment would be
 * describing two different runs, and the two would eventually disagree.
 *
 * The input is a JSON report **this tool produced**. It is still validated
 * rather than trusted: a report file is an ordinary file, it may have been
 * edited, and rendering it into HTML puts its contents in front of a reviewer.
 */
export async function reportCommand(
  argv: readonly string[],
  context: CliContext,
  toolVersion: string
): Promise<ExitCodeValue> {
  const { values, positionals } = parseSafely(argv, {
    format: { type: 'string' },
    out: { type: 'string', short: 'o' },
    'include-root': { type: 'boolean' },
  });

  const input = positionals[0];
  if (input === undefined) {
    throw new CliError('Usage: rn-security report <report.json> --format <format>');
  }

  const format = (values['format'] as string | undefined) ?? 'console';
  const reporter = getReporter(format);

  const source = path.resolve(context.cwd, input);
  const report = parseReport(await read(source), source);

  const output = reporter.render(report, {
    toolVersion,
    includeRoot: values['include-root'] === true,
    colour: false,
  });

  const destination = values['out'] as string | undefined;
  if (destination === undefined) {
    context.stdout(output);
  } else {
    const resolved = path.resolve(context.cwd, destination);
    await fs.writeFile(resolved, output, 'utf8');
    context.stdout(
      `Wrote ${report.findings.length} finding(s) to ${resolved} as ${reporter.name}.\n`
    );
  }

  // Re-rendering reports the same verdict the scan reached; it does not re-judge.
  return report.exceedsFailOn ? ExitCode.FindingsAtOrAboveThreshold : ExitCode.Ok;
}

async function read(source: string): Promise<string> {
  try {
    return await fs.readFile(source, 'utf8');
  } catch (error: unknown) {
    throw new CliError(
      `Cannot read ${source}: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * Turns a JSON document into a report, refusing anything that is not one.
 *
 * The JSON reporter writes an envelope with the report inside it, so both the
 * envelope and a bare report are accepted. Everything else is rejected with a
 * message that says what was expected — a reporter fed a half-report produces
 * confident nonsense.
 */
function parseReport(text: string, source: string): AuditReport {
  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch (error: unknown) {
    throw new CliError(
      `${source} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  if (typeof document !== 'object' || document === null || Array.isArray(document)) {
    throw new CliError(`${source} does not contain a report object.`);
  }

  const record = document as Record<string, unknown>;
  const candidate = (record['schemaVersion'] === undefined ? record : record) as Record<
    string,
    unknown
  >;

  const required = ['findings', 'stats', 'failOn'];
  const missing = required.filter((field) => candidate[field] === undefined);

  // The JSON envelope keeps `failOn` under `summary`; a bare report has it at
  // the top level. Accept both rather than making the caller reshape it.
  if (
    missing.length > 0 &&
    typeof candidate['summary'] === 'object' &&
    candidate['summary'] !== null
  ) {
    const summary = candidate['summary'] as Record<string, unknown>;
    const scan = (candidate['scan'] ?? {}) as Record<string, unknown>;
    return {
      startedAt: (scan['startedAt'] as string | undefined) ?? new Date(0).toISOString(),
      durationMs: (scan['durationMs'] as number | undefined) ?? 0,
      root: (candidate['root'] as string | undefined) ?? '',
      findings: (candidate['findings'] ?? []) as AuditReport['findings'],
      suppressed: (candidate['suppressed'] ?? []) as AuditReport['suppressed'],
      skipped: (candidate['skipped'] ?? []) as AuditReport['skipped'],
      ruleErrors: (candidate['ruleErrors'] ?? []) as AuditReport['ruleErrors'],
      suppressionErrors: (candidate['suppressionErrors'] ?? []) as AuditReport['suppressionErrors'],
      stats: candidate['stats'] as AuditReport['stats'],
      truncated: scan['truncated'] === true,
      timedOut: scan['timedOut'] === true,
      failOn: (summary['failOn'] ?? 'high') as AuditReport['failOn'],
      exceedsFailOn: summary['exceedsFailOn'] === true,
      aiUsed: scan['aiUsed'] === true,
    };
  }

  if (missing.length > 0) {
    throw new CliError(
      `${source} is missing ${missing.join(', ')}. Pass a report written by "rn-security audit --format json".`
    );
  }

  return candidate as unknown as AuditReport;
}
