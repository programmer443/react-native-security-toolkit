import { DEFAULT_EXCLUDE, defaultConfig, defaultLimits } from './defaults.js';
import type { AuditorConfig, RuleOverride, ScanLimits, SuppressionEntry } from '../types/config.js';
import type { Severity } from '../types/finding.js';

/**
 * Validation of caller-supplied configuration.
 *
 * Mistakes are thrown, never corrected. A misspelled key that silently does
 * nothing is how a project ends up believing a rule is disabled, or a directory
 * excluded, when neither is true — and configuration is exactly where a
 * security tool's silence is most expensive.
 */
export class AuditorConfigError extends Error {
  constructor(message: string) {
    super(`Invalid auditor configuration: ${message}`);
    this.name = 'AuditorConfigError';
  }
}

const PROFILES = ['minimal', 'standard', 'strict'] as const;
const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** Lowest severity each profile reports. */
const PROFILE_MINIMUM: Readonly<Record<(typeof PROFILES)[number], Severity>> = {
  minimal: 'high',
  standard: 'low',
  strict: 'info',
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireStringArray(value: unknown, field: string): readonly string[] {
  if (!Array.isArray(value)) {
    throw new AuditorConfigError(`"${field}" must be an array of strings`);
  }
  return value.map((entry) => {
    if (typeof entry !== 'string' || entry.trim().length === 0) {
      throw new AuditorConfigError(`"${field}" must contain only non-empty strings`);
    }
    return entry;
  });
}

function requireSeverity(value: unknown, field: string): Severity {
  if (typeof value !== 'string' || !SEVERITIES.includes(value as Severity)) {
    throw new AuditorConfigError(`"${field}" must be one of ${SEVERITIES.join(', ')}`);
  }
  return value as Severity;
}

function resolveLimits(value: unknown): ScanLimits {
  const base = defaultLimits();
  if (value === undefined) {
    return base;
  }
  if (!isRecord(value)) {
    throw new AuditorConfigError('"limits" must be an object');
  }

  const resolved: Record<string, number> = { ...base };
  for (const [key, limit] of Object.entries(value)) {
    if (!(key in base)) {
      throw new AuditorConfigError(
        `"limits.${key}" is not a known limit. Known limits: ${Object.keys(base).join(', ')}`
      );
    }
    if (typeof limit !== 'number' || !Number.isFinite(limit) || limit <= 0) {
      throw new AuditorConfigError(`"limits.${key}" must be a positive, finite number`);
    }
    resolved[key] = limit;
  }
  return resolved as unknown as ScanLimits;
}

function resolveOverrides(value: unknown): readonly RuleOverride[] {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new AuditorConfigError(
      '"rules.overrides" must be an array, for example [{ rule: "RNSEC-LOG-001", severity: "low" }]'
    );
  }

  return value.map((entry, index) => {
    if (!isRecord(entry)) {
      throw new AuditorConfigError(`"rules.overrides[${index}]" must be an object`);
    }
    const rule = entry['rule'];
    if (typeof rule !== 'string' || rule.length === 0) {
      throw new AuditorConfigError(`"rules.overrides[${index}].rule" must be a rule identifier`);
    }
    const severity =
      entry['severity'] === undefined
        ? undefined
        : requireSeverity(entry['severity'], `rules.overrides[${index}].severity`);
    const paths =
      entry['paths'] === undefined
        ? undefined
        : requireStringArray(entry['paths'], `rules.overrides[${index}].paths`);

    if (severity === undefined && paths === undefined) {
      throw new AuditorConfigError(
        `"rules.overrides[${index}]" changes nothing. Give it a severity, or remove it.`
      );
    }

    return {
      rule,
      ...(severity === undefined ? {} : { severity }),
      ...(paths === undefined ? {} : { paths }),
    };
  });
}

/**
 * Validates baseline entries.
 *
 * A reason is mandatory (§43). An unexplained baseline entry is a finding
 * somebody hid, and there is no way to tell later whether it was reviewed.
 */
function resolveIgnore(value: unknown): readonly SuppressionEntry[] {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new AuditorConfigError('"ignore" must be an array of { fingerprint, reason } entries');
  }

  return value.map((entry, index) => {
    if (!isRecord(entry)) {
      throw new AuditorConfigError(`"ignore[${index}]" must be an object`);
    }
    const fingerprint = entry['fingerprint'];
    const reason = entry['reason'];
    if (typeof fingerprint !== 'string' || !/^[0-9a-f]{8,64}$/.test(fingerprint)) {
      throw new AuditorConfigError(
        `"ignore[${index}].fingerprint" must be a fingerprint from a previous report`
      );
    }
    if (typeof reason !== 'string' || reason.trim().length === 0) {
      throw new AuditorConfigError(
        `"ignore[${index}].reason" is required. A suppression without a reason cannot be reviewed later.`
      );
    }
    return { fingerprint, reason: reason.trim() };
  });
}

/**
 * Turns caller-supplied options into a resolved configuration.
 *
 * User `exclude` patterns **extend** the defaults rather than replacing them.
 * Replacing them is a footgun: a project that adds one exclusion would silently
 * start scanning `node_modules`, and the first sign would be a scan that never
 * finishes.
 */
export function resolveConfig(options: unknown): AuditorConfig {
  const base = defaultConfig();

  if (options === undefined || options === null) {
    return base;
  }
  if (!isRecord(options)) {
    throw new AuditorConfigError('expected an object');
  }

  const known = ['profile', 'include', 'exclude', 'rules', 'ignore', 'severity', 'limits', 'ai'];
  for (const key of Object.keys(options)) {
    if (!known.includes(key)) {
      throw new AuditorConfigError(
        `"${key}" is not a known option. Known options: ${known.join(', ')}`
      );
    }
  }

  const profileValue = options['profile'];
  if (profileValue !== undefined && !PROFILES.includes(profileValue as (typeof PROFILES)[number])) {
    throw new AuditorConfigError(`"profile" must be one of ${PROFILES.join(', ')}`);
  }
  const profile = (profileValue as (typeof PROFILES)[number] | undefined) ?? base.profile;

  const include =
    options['include'] === undefined ? [] : requireStringArray(options['include'], 'include');
  const exclude =
    options['exclude'] === undefined
      ? [...DEFAULT_EXCLUDE]
      : [...DEFAULT_EXCLUDE, ...requireStringArray(options['exclude'], 'exclude')];

  const rules = options['rules'];
  if (rules !== undefined && !isRecord(rules)) {
    throw new AuditorConfigError('"rules" must be an object');
  }
  const disabledRules =
    rules?.['disabled'] === undefined
      ? []
      : requireStringArray(rules['disabled'], 'rules.disabled');
  const ruleOverrides = resolveOverrides(rules?.['overrides']);

  const severity = options['severity'];
  if (severity !== undefined && !isRecord(severity)) {
    throw new AuditorConfigError('"severity" must be an object');
  }
  const failOn =
    severity?.['failOn'] === undefined
      ? base.failOn
      : requireSeverity(severity['failOn'], 'severity.failOn');
  const minimumSeverity =
    severity?.['minimum'] === undefined
      ? PROFILE_MINIMUM[profile]
      : requireSeverity(severity['minimum'], 'severity.minimum');

  const ai = options['ai'];
  if (ai !== undefined) {
    if (!isRecord(ai)) {
      throw new AuditorConfigError('"ai" must be an object');
    }
    if (ai['enabled'] === true) {
      // There is no vendor AI in this package to switch on, and accepting the
      // flag would leave a project believing an analysis ran that never did.
      // AI assistance in this toolkit works the other way round: the MCP server
      // hands these findings to whichever model the developer already uses, so
      // no key, no upload and no vendor lives here.
      throw new AuditorConfigError(
        'This package runs no AI analysis, so "ai.enabled" has nothing to enable. For AI-assisted ' +
          'review, run the MCP server and connect your own model — see docs/mcp.md. Remove the key ' +
          'or set it to false.'
      );
    }
    if (ai['enabled'] !== undefined && typeof ai['enabled'] !== 'boolean') {
      throw new AuditorConfigError('"ai.enabled" must be a boolean');
    }
  }

  return {
    profile,
    include,
    exclude,
    disabledRules,
    ruleOverrides,
    ignore: resolveIgnore(options['ignore']),
    failOn,
    minimumSeverity,
    limits: resolveLimits(options['limits']),
    ai: { enabled: false },
  };
}
