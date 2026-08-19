import { parseArgs } from 'node:util';
import path from 'node:path';

import { CliError } from './context.js';
import type { CliContext } from './context.js';

/**
 * Argument parsing, on Node's own `parseArgs`.
 *
 * No argument-parsing dependency: this is a security tool, every dependency is a
 * supply-chain decision, and the platform has covered this since Node 18. What
 * the library would add — subcommand routing and help text — is thirty lines
 * here.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const FORMATS = ['console', 'json', 'markdown', 'html', 'sarif'] as const;

export type Format = (typeof FORMATS)[number];

export interface ScanOptions {
  /** Absolute path of the project to scan. */
  readonly target: string;
  readonly format: Format;
  /** File to write to. Absent means stdout. */
  readonly out?: string;
  /** Severity at which the command exits non-zero. Overrides configuration. */
  readonly failOn?: Severity;
  /** Findings below this severity are counted, not listed. Overrides configuration. */
  readonly minimum?: Severity;
  /** Explicit configuration file, overriding discovery. */
  readonly config?: string;
  readonly includeRoot: boolean;
  readonly colour: boolean;
}

const SCAN_FLAGS = {
  format: { type: 'string' as const },
  out: { type: 'string' as const, short: 'o' },
  'fail-on': { type: 'string' as const },
  min: { type: 'string' as const },
  config: { type: 'string' as const, short: 'c' },
  'include-root': { type: 'boolean' as const },
  color: { type: 'boolean' as const },
  'no-color': { type: 'boolean' as const },
};

/** Parses the flags shared by every scanning command. */
export function parseScanOptions(argv: readonly string[], context: CliContext): ScanOptions {
  const { values, positionals } = parseSafely(argv, SCAN_FLAGS);

  const format =
    requireOneOf(values['format'] as string | undefined, FORMATS, 'format') ?? 'console';
  const failOn = requireOneOf(values['fail-on'] as string | undefined, SEVERITIES, 'fail-on');
  const minimum = requireOneOf(values['min'] as string | undefined, SEVERITIES, 'min');

  if (values['color'] === true && values['no-color'] === true) {
    throw new CliError('--color and --no-color contradict each other.');
  }

  const colour =
    values['no-color'] === true
      ? false
      : values['color'] === true
        ? true
        : // Colour when a person is watching and the output is not going to a file.
          context.isTty && values['out'] === undefined && format === 'console';

  return {
    target: path.resolve(context.cwd, positionals[0] ?? '.'),
    format,
    ...(values['out'] === undefined
      ? {}
      : { out: path.resolve(context.cwd, values['out'] as string) }),
    ...(failOn === undefined ? {} : { failOn }),
    ...(minimum === undefined ? {} : { minimum }),
    ...(values['config'] === undefined
      ? {}
      : { config: path.resolve(context.cwd, values['config'] as string) }),
    includeRoot: values['include-root'] === true,
    colour,
  };
}

/**
 * Wraps `parseArgs` so an unknown flag produces advice rather than a stack trace.
 *
 * A mistyped flag that is silently ignored is how someone ends up believing they
 * ran with `--fail-on critical` when they did not.
 */
export function parseSafely<
  T extends Record<string, { type: 'string' | 'boolean'; short?: string }>,
>(argv: readonly string[], flags: T): { values: Record<string, unknown>; positionals: string[] } {
  try {
    const parsed = parseArgs({
      args: [...argv],
      options: flags,
      allowPositionals: true,
      strict: true,
    });
    return { values: parsed.values as Record<string, unknown>, positionals: parsed.positionals };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    throw new CliError(
      `${message}\nKnown flags: ${Object.keys(flags)
        .map((flag) => `--${flag}`)
        .join(', ')}`
    );
  }
}

function requireOneOf<T extends string>(
  value: string | undefined,
  allowed: readonly T[],
  flag: string
): T | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!allowed.includes(value as T)) {
    throw new CliError(`--${flag} must be one of ${allowed.join(', ')}. Received "${value}".`);
  }
  return value as T;
}

export { FORMATS, SEVERITIES };
