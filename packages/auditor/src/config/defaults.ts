import os from 'node:os';

import type { AuditorConfig, ScanLimits } from '../types/config.js';

/**
 * Paths excluded unless a project says otherwise.
 *
 * These are all directories whose contents are *not the project's own code*:
 * dependencies, build output and vendored sources. Scanning them produces
 * findings nobody can fix, in volumes that bury the ones they can.
 */
export const DEFAULT_EXCLUDE: readonly string[] = Object.freeze([
  '**/node_modules/**',
  '**/.git/**',
  '**/build/**',
  '**/dist/**',
  '**/lib/**',
  '**/out/**',
  '**/coverage/**',
  '**/.gradle/**',
  '**/.build/**',
  '**/.cxx/**',
  '**/.expo/**',
  '**/.next/**',
  '**/Pods/**',
  '**/Carthage/**',
  '**/DerivedData/**',
  '**/vendor/bundle/**',
  '**/*.min.js',
  '**/*.map',
  '**/*.generated.*',
]);

/**
 * Bounds that hold whatever the repository contains.
 *
 * Concurrency leaves a core free: the auditor is a developer tool, and one that
 * makes a laptop unusable while it runs gets switched off, which is a security
 * outcome as surely as a missed finding is.
 */
export function defaultLimits(): ScanLimits {
  const parallelism =
    typeof os.availableParallelism === 'function' ? os.availableParallelism() : os.cpus().length;

  return {
    maxFileBytes: 1_048_576,
    maxFiles: 20_000,
    maxTotalBytes: 134_217_728,
    maxDepth: 24,
    maxParseBytes: 524_288,
    concurrency: Math.max(1, parallelism - 1),
    timeoutMs: 120_000,
  };
}

/** The configuration a project gets when it supplies none. */
export function defaultConfig(): AuditorConfig {
  return {
    profile: 'standard',
    include: [],
    exclude: [...DEFAULT_EXCLUDE],
    disabledRules: [],
    ruleOverrides: [],
    ignore: [],
    failOn: 'high',
    minimumSeverity: 'low',
    limits: defaultLimits(),
    // AI is opt-in, everywhere, always (§28/§54). Nothing in this phase can
    // switch it on.
    ai: { enabled: false },
  };
}
