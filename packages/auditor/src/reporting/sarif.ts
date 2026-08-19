import { TOOL_INFORMATION_URI, TOOL_NAME, coverageWarning } from './types.js';
import { knowledge } from '../knowledge/index.js';
import type { ReportOptions, Reporter } from './types.js';
import type { AuditReport, SuppressedFindingReport } from '../types/report.js';
import type { SecurityFinding, Severity } from '../types/finding.js';

/**
 * SARIF 2.1.0, for GitHub code scanning and anything else that speaks it.
 *
 * The parts that are easy to get subtly wrong, and what this reporter does about
 * them:
 *
 * - **`level` is not severity.** SARIF has three useful levels; the audit has
 *   five severities. The mapping is stated once, below, and GitHub reads the
 *   finer detail from the `security-severity` property instead.
 * - **`security-severity` is a *string* holding a number.** GitHub buckets it
 *   into its own critical/high/medium/low. Omitting it makes every alert
 *   "warning" regardless of what the report said.
 * - **Fingerprints are the whole point of `partialFingerprints`.** Ours already
 *   exclude line numbers, which is exactly the property that lets an alert
 *   survive the file being edited above it.
 * - **Suppressed findings are still results.** A result carrying a `suppressions`
 *   entry is shown as dismissed rather than dropped — which is more honest than
 *   silently omitting it, and preserves the reason.
 * - **URIs are relative.** An absolute local path in a SARIF file is both a leak
 *   and useless to whatever ingests it; `%SRCROOT%` is the base id.
 */

const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const SARIF_VERSION = '2.1.0';

/** Audit severity to SARIF level. */
function levelOf(severity: Severity): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    default:
      return 'note';
  }
}

/**
 * Audit severity to a CVSS-style number, as GitHub buckets it.
 *
 * These are band midpoints, not a CVSS calculation: the auditor does not compute
 * a CVSS vector, and pretending otherwise would be a fabricated precision.
 */
function securitySeverityOf(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return '9.3';
    case 'high':
      return '7.5';
    case 'medium':
      return '5.0';
    case 'low':
      return '3.0';
    case 'info':
      return '0.5';
  }
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string; markdown: string };
  defaultConfiguration: { level: 'error' | 'warning' | 'note' };
  properties: { tags: string[]; 'security-severity': string; precision: string };
}

export const sarifReporter: Reporter = {
  name: 'sarif',
  extension: 'sarif',
  contentType: 'application/sarif+json; charset=utf-8',

  render(report: AuditReport, options?: ReportOptions): string {
    const rules: SarifRule[] = [];
    const ruleIndex = new Map<string, number>();

    // Only rules that produced something are described, which is what SARIF
    // expects and keeps the file proportional to the findings.
    const all = [...report.findings, ...report.suppressed.map((entry) => entry.finding)];
    for (const finding of all) {
      if (ruleIndex.has(finding.ruleId)) {
        continue;
      }
      ruleIndex.set(finding.ruleId, rules.length);
      rules.push(describeRule(finding));
    }

    const results = [
      ...report.findings.map((finding) => toResult(finding, ruleIndex)),
      ...report.suppressed.map((entry) => toSuppressedResult(entry, ruleIndex)),
    ];

    const document = {
      $schema: SARIF_SCHEMA,
      version: SARIF_VERSION,
      runs: [
        {
          tool: {
            driver: {
              name: TOOL_NAME,
              version: options?.toolVersion ?? '0.0.0',
              informationUri: TOOL_INFORMATION_URI,
              rules,
              properties: { knowledgeSnapshot: knowledge.version },
            },
          },
          // `%SRCROOT%` lets a consumer resolve relative artifact URIs without
          // the report carrying anyone's home directory.
          originalUriBaseIds: {
            '%SRCROOT%': {
              uri: options?.includeRoot === true ? toFileUri(report.root) : 'file:///',
            },
          },
          invocations: [
            {
              executionSuccessful: report.ruleErrors.length === 0,
              startTimeUtc: report.startedAt,
              ...(report.ruleErrors.length === 0 && coverageWarning(report) === undefined
                ? {}
                : { toolExecutionNotifications: notifications(report) }),
            },
          ],
          results,
          properties: {
            truncated: report.truncated,
            timedOut: report.timedOut,
            aiUsed: report.aiUsed,
            findingsBelowThreshold: report.stats.findingsBelowThreshold,
          },
        },
      ],
    };

    return `${JSON.stringify(document, null, 2)}\n`;
  },
};

function describeRule(finding: SecurityFinding): SarifRule {
  const references = [
    ...(finding.cwe ?? []),
    ...(finding.maswe ?? []),
    ...(finding.masvs ?? []),
    ...(finding.mastg ?? []),
  ];

  const help = [
    finding.description,
    '',
    `**Impact.** ${finding.impact}`,
    '',
    `**Exploitability.** ${finding.exploitability}`,
    '',
    `**Fix.** ${finding.remediation}`,
    ...(references.length === 0
      ? []
      : ['', `**Standards.** ${references.map((reference) => reference.id).join(', ')}`]),
  ].join('\n');

  return {
    id: finding.ruleId,
    name: toPascalCase(finding.ruleId),
    shortDescription: { text: finding.title },
    fullDescription: { text: finding.description },
    help: { text: help.replace(/\*\*/g, ''), markdown: help },
    defaultConfiguration: { level: levelOf(finding.severity) },
    properties: {
      // `security` is what makes GitHub treat these as security alerts; the
      // standards identifiers become filterable tags.
      tags: ['security', ...finding.categories, ...references.map((reference) => reference.id)],
      'security-severity': securitySeverityOf(finding.severity),
      precision: precisionOf(finding.confidence),
    },
  };
}

/** SARIF's vocabulary for how much a finding can be trusted. */
function precisionOf(confidence: SecurityFinding['confidence']): string {
  switch (confidence) {
    case 'very-high':
      return 'very-high';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    default:
      return 'low';
  }
}

function toResult(finding: SecurityFinding, ruleIndex: ReadonlyMap<string, number>): object {
  const region =
    finding.location.line === undefined
      ? undefined
      : {
          startLine: finding.location.line,
          ...(finding.location.column === undefined
            ? {}
            : { startColumn: finding.location.column }),
          ...(finding.location.endLine === undefined ? {} : { endLine: finding.location.endLine }),
        };

  return {
    ruleId: finding.ruleId,
    ruleIndex: ruleIndex.get(finding.ruleId) ?? 0,
    level: levelOf(finding.severity),
    message: { text: `${finding.title}. ${finding.description}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: toUriReference(finding.location.path), uriBaseId: '%SRCROOT%' },
          ...(region === undefined ? {} : { region }),
        },
      },
    ],
    // Line-number-free by construction, so an alert survives edits above it.
    partialFingerprints: { rnsecFingerprint: finding.fingerprint },
    properties: {
      severity: finding.severity,
      confidence: finding.confidence,
      categories: finding.categories,
      ...(finding.severityAdjustment === undefined
        ? {}
        : { severityAdjustment: finding.severityAdjustment }),
    },
  };
}

function toSuppressedResult(
  entry: SuppressedFindingReport,
  ruleIndex: ReadonlyMap<string, number>
): object {
  return {
    ...toResult(entry.finding, ruleIndex),
    suppressions: [
      {
        // `inSource` is a directive in the code; a baseline or configuration
        // entry lives outside it.
        kind: entry.kind === 'inline' ? 'inSource' : 'external',
        justification: entry.reason,
      },
    ],
  };
}

function notifications(report: AuditReport): object[] {
  const entries: object[] = [];

  const warning = coverageWarning(report);
  if (warning !== undefined) {
    entries.push({
      level: 'warning',
      message: { text: warning },
      descriptor: { id: 'RNSEC-SCAN-INCOMPLETE' },
    });
  }

  for (const error of report.ruleErrors) {
    entries.push({
      level: 'error',
      message: { text: `Rule ${error.ruleId} failed on ${error.path}: ${error.message}` },
      descriptor: { id: 'RNSEC-RULE-ERROR' },
    });
  }

  return entries;
}

/** `RNSEC-SECRET-001` becomes `RnsecSecret001`, which is what SARIF wants for `name`. */
function toPascalCase(ruleId: string): string {
  return ruleId
    .split('-')
    .map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1).toLowerCase()}`)
    .join('');
}

/**
 * Percent-encodes a project-relative path so it is a valid URI reference.
 *
 * File names are attacker-controlled, and `src/<img src=x onerror=alert(1)>.ts`
 * is a legal POSIX filename that is not a legal URI. Emitting it raw produces a
 * SARIF file that fails schema validation — which GitHub rejects silently from
 * the developer's point of view. Segments are encoded individually so the path
 * separators survive.
 */
function toUriReference(projectPath: string): string {
  return projectPath.split('/').map(encodeURIComponent).join('/');
}

function toFileUri(absolutePath: string): string {
  const normalised = absolutePath.replace(/\\/g, '/');
  return `file://${normalised.startsWith('/') ? '' : '/'}${normalised}${normalised.endsWith('/') ? '' : '/'}`;
}
