import { SEVERITY_ORDER, countBySeverity, coverageWarning } from './types.js';
import type { ReportOptions, Reporter } from './types.js';
import type { AuditReport } from '../types/report.js';
import type { SecurityFinding, Severity } from '../types/finding.js';

/**
 * The format a developer actually reads.
 *
 * Ordered by severity, one block per finding, with the reasoning attached: what
 * was found, how confident the rule is, whether the severity was adjusted and
 * why, and which standards it maps to. A console report that prints only a count
 * teaches people to ignore it.
 *
 * Colour is off unless the caller asks. Piping a report into a file and finding
 * it full of escape codes is a small thing that makes a tool feel careless.
 */

const ANSI = {
  reset: '\u001b[0m',
  red: '\u001b[31m',
  yellow: '\u001b[33m',
  blue: '\u001b[34m',
  grey: '\u001b[90m',
} as const;

const SEVERITY_COLOUR: Readonly<Record<Severity, string>> = {
  critical: ANSI.red,
  high: ANSI.red,
  medium: ANSI.yellow,
  low: ANSI.blue,
  info: ANSI.grey,
};

export const consoleReporter: Reporter = {
  name: 'console',
  extension: 'txt',
  contentType: 'text/plain; charset=utf-8',

  render(report: AuditReport, options?: ReportOptions): string {
    const paint = (text: string, colour: string): string =>
      options?.colour === true ? `${colour}${text}${ANSI.reset}` : text;

    const lines: string[] = [];

    if (options?.includeRoot === true) {
      lines.push(`Scanned ${report.root}`);
    }
    lines.push(
      `${report.stats.filesAnalysed} of ${report.stats.filesDiscovered} discovered files analysed ` +
        `in ${report.durationMs}ms, ${report.stats.rulesRun} rules`
    );

    const warning = coverageWarning(report);
    if (warning !== undefined) {
      lines.push(paint(warning, ANSI.yellow));
    }
    lines.push('');

    if (report.findings.length === 0) {
      lines.push('No findings.');
    }

    for (const finding of report.findings) {
      lines.push(...renderFinding(finding, paint));
    }

    lines.push(...renderSummary(report, paint));
    return `${lines.join('\n')}\n`;
  },
};

function renderFinding(
  finding: SecurityFinding,
  paint: (text: string, colour: string) => string
): readonly string[] {
  const location = `${finding.location.path}${finding.location.line === undefined ? '' : `:${finding.location.line}`}`;
  const lines: string[] = [
    `${paint(finding.severity.toUpperCase().padEnd(8), SEVERITY_COLOUR[finding.severity])} ${finding.ruleId}  ${location}`,
    `  ${finding.title}`,
    `  ${finding.description}`,
    `  confidence: ${finding.confidence}`,
  ];

  if (finding.severityAdjustment !== undefined) {
    // A downgrade that cannot be traced back to the rule that applied it is
    // indistinguishable from a missed finding.
    lines.push(
      `  severity adjusted from ${finding.severityAdjustment.from}: ${finding.severityAdjustment.reason}`
    );
  }

  for (const evidence of finding.evidence) {
    // The line matters: a rule that found the same pattern nine times in one
    // file merges into one finding, and without the line numbers the evidence
    // reads as the same fact repeated rather than as nine occurrences.
    const where = evidence.line === undefined ? '' : ` (line ${evidence.line})`;
    const snippet = evidence.snippet === undefined ? '' : `  ${evidence.snippet}`;
    lines.push(`  evidence: ${evidence.description}${where}${snippet}`);
  }

  const references = [
    ...(finding.cwe ?? []),
    ...(finding.maswe ?? []),
    ...(finding.masvs ?? []),
    ...(finding.mastg ?? []),
  ];
  if (references.length > 0) {
    lines.push(`  standards: ${references.map((reference) => reference.id).join(', ')}`);
  }

  lines.push(`  fix: ${finding.remediation}`);
  lines.push(`  fingerprint: ${finding.fingerprint}`);
  lines.push('');
  return lines;
}

function renderSummary(
  report: AuditReport,
  paint: (text: string, colour: string) => string
): readonly string[] {
  const counts = countBySeverity(report);
  const parts = SEVERITY_ORDER.filter((severity) => counts[severity] > 0).map(
    (severity) => `${counts[severity]} ${severity}`
  );

  const lines = [parts.length === 0 ? 'Summary: no findings' : `Summary: ${parts.join(', ')}`];

  if (report.suppressed.length > 0) {
    lines.push(`${report.suppressed.length} finding(s) suppressed, each with a recorded reason.`);
  }
  if (report.stats.findingsBelowThreshold > 0) {
    lines.push(
      `${report.stats.findingsBelowThreshold} finding(s) below the reporting threshold were not listed.`
    );
  }
  if (report.suppressionErrors.length > 0) {
    lines.push(`${report.suppressionErrors.length} suppression directive(s) were ignored:`);
    for (const error of report.suppressionErrors) {
      lines.push(`  ${error.path}:${error.line} ${error.message}`);
    }
  }
  if (report.ruleErrors.length > 0) {
    lines.push(`${report.ruleErrors.length} rule error(s):`);
    for (const error of report.ruleErrors) {
      lines.push(`  ${error.ruleId} on ${error.path}: ${error.message}`);
    }
  }

  lines.push(
    report.exceedsFailOn
      ? paint(`At least one finding meets the failure threshold (${report.failOn}).`, ANSI.red)
      : `No finding meets the failure threshold (${report.failOn}).`
  );

  return lines;
}
