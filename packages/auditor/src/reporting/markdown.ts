import { SEVERITY_ORDER, countBySeverity, coverageWarning } from './types.js';
import type { ReportOptions, Reporter } from './types.js';
import type { AuditReport } from '../types/report.js';
import type { SecurityFinding } from '../types/finding.js';

/**
 * Markdown, for a pull request comment or a job summary.
 *
 * The constraint that shapes this format is that **the content is untrusted**:
 * titles, snippets and paths all come from the repository under analysis. A
 * snippet containing a backtick or a pipe would otherwise break out of its code
 * span or its table cell — turning a report into mangled output, and in a table
 * into something that can misrepresent which file a finding belongs to.
 */

export const markdownReporter: Reporter = {
  name: 'markdown',
  extension: 'md',
  contentType: 'text/markdown; charset=utf-8',

  render(report: AuditReport, options?: ReportOptions): string {
    const counts = countBySeverity(report);
    const lines: string[] = ['# Security audit', ''];

    if (options?.includeRoot === true) {
      lines.push(`Scanned \`${escapeInline(report.root)}\``, '');
    }

    const warning = coverageWarning(report);
    if (warning !== undefined) {
      lines.push(`> [!WARNING]`, `> ${warning}`, '');
    }

    lines.push(
      '| Severity | Findings |',
      '| -------- | -------- |',
      ...SEVERITY_ORDER.map((severity) => `| ${severity} | ${counts[severity]} |`),
      '',
      `${report.stats.filesAnalysed} of ${report.stats.filesDiscovered} discovered files analysed ` +
        `in ${report.durationMs}ms, across ${report.stats.rulesRun} rules.`,
      ''
    );

    if (report.findings.length === 0) {
      lines.push('No findings.', '');
    }

    for (const severity of SEVERITY_ORDER) {
      const group = report.findings.filter((finding) => finding.severity === severity);
      if (group.length === 0) {
        continue;
      }
      lines.push(`## ${capitalise(severity)}`, '');
      for (const finding of group) {
        lines.push(...renderFinding(finding));
      }
    }

    lines.push(...renderFooter(report));
    return `${lines.join('\n')}\n`;
  },
};

function renderFinding(finding: SecurityFinding): readonly string[] {
  const location = `${finding.location.path}${finding.location.line === undefined ? '' : `:${finding.location.line}`}`;
  const lines: string[] = [
    `### ${escapeInline(finding.title)}`,
    '',
    `\`${escapeInline(finding.ruleId)}\` · \`${escapeInline(location)}\` · confidence ${finding.confidence}`,
    '',
    escapeInline(finding.description),
    '',
  ];

  if (finding.severityAdjustment !== undefined) {
    lines.push(
      `Severity adjusted from **${finding.severityAdjustment.from}**: ${escapeInline(finding.severityAdjustment.reason)}`,
      ''
    );
  }

  if (finding.codeSnippet !== undefined) {
    // A fenced block, not an inline span: a snippet can contain anything,
    // including backticks.
    lines.push('```', fenceSafe(finding.codeSnippet), '```', '');
  }

  const references = [
    ...(finding.cwe ?? []),
    ...(finding.maswe ?? []),
    ...(finding.masvs ?? []),
    ...(finding.mastg ?? []),
  ];
  if (references.length > 0) {
    lines.push(
      `**Standards:** ${references.map((reference) => `${escapeInline(reference.id)}${reference.title === undefined ? '' : ` (${escapeInline(reference.title)})`}`).join(', ')}`,
      ''
    );
  }

  lines.push(
    `**Impact:** ${escapeInline(finding.impact)}`,
    '',
    `**Exploitability:** ${escapeInline(finding.exploitability)}`,
    '',
    `**Fix:** ${escapeInline(finding.remediation)}`,
    '',
    `<sub>fingerprint \`${escapeInline(finding.fingerprint)}\` — use it to suppress this finding with a reason</sub>`,
    ''
  );

  return lines;
}

function renderFooter(report: AuditReport): readonly string[] {
  const lines: string[] = ['---', ''];

  if (report.suppressed.length > 0) {
    lines.push(
      `${report.suppressed.length} finding(s) suppressed, each with a recorded reason.`,
      ''
    );
  }
  if (report.stats.findingsBelowThreshold > 0) {
    lines.push(
      `${report.stats.findingsBelowThreshold} finding(s) below the reporting threshold were not listed.`,
      ''
    );
  }
  if (report.suppressionErrors.length > 0) {
    lines.push(`**${report.suppressionErrors.length} suppression directive(s) were ignored:**`, '');
    for (const error of report.suppressionErrors) {
      lines.push(`- \`${escapeInline(error.path)}:${error.line}\` ${escapeInline(error.message)}`);
    }
    lines.push('');
  }
  if (report.ruleErrors.length > 0) {
    lines.push(`**${report.ruleErrors.length} rule error(s):**`, '');
    for (const error of report.ruleErrors) {
      lines.push(
        `- \`${escapeInline(error.ruleId)}\` on \`${escapeInline(error.path)}\`: ${escapeInline(error.message)}`
      );
    }
    lines.push('');
  }

  lines.push(
    report.exceedsFailOn
      ? `At least one finding meets the failure threshold (**${report.failOn}**).`
      : `No finding meets the failure threshold (**${report.failOn}**).`
  );

  return lines;
}

/**
 * Neutralises markdown control characters in untrusted text.
 *
 * Pipes are escaped because an unescaped one splits a table cell; backticks,
 * angle brackets and the emphasis characters are escaped because a crafted file
 * path should not be able to restyle the report it appears in.
 */
function escapeInline(text: string): string {
  return text
    .replace(/[\\`*_{}[\]()#+\-.!|<>]/g, (character) => `\\${character}`)
    .replace(/\r?\n/g, ' ');
}

/** Makes a snippet safe to place inside a fenced block. */
function fenceSafe(text: string): string {
  return text.replace(/```/g, '` ` `').replace(/\r?\n/g, ' ');
}

function capitalise(text: string): string {
  return `${text.slice(0, 1).toUpperCase()}${text.slice(1)}`;
}
