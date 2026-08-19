import { SEVERITY_ORDER, TOOL_NAME, countBySeverity, coverageWarning, timestamp } from './types.js';
import { knowledge } from '../knowledge/index.js';
import type { ReportOptions, Reporter } from './types.js';
import type { AuditReport } from '../types/report.js';
import type { SecurityFinding } from '../types/finding.js';

/**
 * A single self-contained HTML file.
 *
 * **Everything in a finding is attacker-controlled.** File paths, code snippets
 * and rule messages all originate in the repository under analysis, and a report
 * is opened in a browser — frequently from a CI artefact, on a machine that
 * trusts it. A scanner whose report executes a `<script>` planted in a filename
 * has handed the attacker the reviewer's browser.
 *
 * So: every interpolation goes through `escapeHtml`, there is no script anywhere
 * in the output, and no external resource is referenced. The file works offline,
 * from a file:// URL, with no network access.
 */

export const htmlReporter: Reporter = {
  name: 'html',
  extension: 'html',
  contentType: 'text/html; charset=utf-8',

  render(report: AuditReport, options?: ReportOptions): string {
    const counts = countBySeverity(report);
    const warning = coverageWarning(report);

    const summaryCells = SEVERITY_ORDER.map(
      (severity) =>
        `<div class="count ${severity}"><span class="n">${counts[severity]}</span><span class="s">${severity}</span></div>`
    ).join('');

    const findings =
      report.findings.length === 0
        ? '<p class="empty">No findings.</p>'
        : report.findings.map(renderFinding).join('\n');

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security audit</title>
<style>${STYLES}</style>
</head>
<body>
<header>
  <h1>Security audit</h1>
  <p class="meta">
    ${escapeHtml(TOOL_NAME)} ${escapeHtml(options?.toolVersion ?? '0.0.0')} ·
    knowledge snapshot ${escapeHtml(knowledge.version)} ·
    generated ${escapeHtml(timestamp(options))}
  </p>
  ${options?.includeRoot === true ? `<p class="meta">Scanned <code>${escapeHtml(report.root)}</code></p>` : ''}
  ${warning === undefined ? '' : `<p class="warning">${escapeHtml(warning)}</p>`}
</header>

<section class="summary">${summaryCells}</section>

<p class="meta">
  ${report.stats.filesAnalysed} of ${report.stats.filesDiscovered} discovered files analysed in
  ${report.durationMs}ms, across ${report.stats.rulesRun} rules.
</p>

<main>
${findings}
</main>

<footer>
${renderFooter(report)}
</footer>
</body>
</html>
`;
  },
};

function renderFinding(finding: SecurityFinding): string {
  const location = `${finding.location.path}${finding.location.line === undefined ? '' : `:${finding.location.line}`}`;

  const references = [
    ...(finding.cwe ?? []),
    ...(finding.maswe ?? []),
    ...(finding.masvs ?? []),
    ...(finding.mastg ?? []),
  ];

  const evidence = finding.evidence
    .map(
      (entry) =>
        `<li>${escapeHtml(entry.description)}${entry.snippet === undefined ? '' : ` <code>${escapeHtml(entry.snippet)}</code>`}</li>`
    )
    .join('');

  return `<article class="finding ${escapeHtml(finding.severity)}">
  <h2>${escapeHtml(finding.title)}</h2>
  <p class="tags">
    <span class="tag severity">${escapeHtml(finding.severity)}</span>
    <span class="tag">${escapeHtml(finding.ruleId)}</span>
    <span class="tag">confidence ${escapeHtml(finding.confidence)}</span>
    <code>${escapeHtml(location)}</code>
  </p>
  <p>${escapeHtml(finding.description)}</p>
  ${
    finding.severityAdjustment === undefined
      ? ''
      : `<p class="adjustment">Severity adjusted from <strong>${escapeHtml(finding.severityAdjustment.from)}</strong>: ${escapeHtml(finding.severityAdjustment.reason)}</p>`
  }
  ${finding.codeSnippet === undefined ? '' : `<pre><code>${escapeHtml(finding.codeSnippet)}</code></pre>`}
  ${evidence === '' ? '' : `<h3>Evidence</h3><ul>${evidence}</ul>`}
  <h3>Impact</h3><p>${escapeHtml(finding.impact)}</p>
  <h3>Exploitability</h3><p>${escapeHtml(finding.exploitability)}</p>
  <h3>Fix</h3><p>${escapeHtml(finding.remediation)}</p>
  ${
    references.length === 0
      ? ''
      : `<h3>Standards</h3><ul class="standards">${references
          .map(
            (reference) =>
              `<li><code>${escapeHtml(reference.id)}</code>${reference.title === undefined ? '' : ` ${escapeHtml(reference.title)}`} <span class="tag">${escapeHtml(reference.mappingConfidence)} confidence mapping</span></li>`
          )
          .join('')}</ul>`
  }
  <p class="fingerprint">fingerprint <code>${escapeHtml(finding.fingerprint)}</code></p>
</article>`;
}

function renderFooter(report: AuditReport): string {
  const parts: string[] = [];

  if (report.suppressed.length > 0) {
    parts.push(
      `<p>${report.suppressed.length} finding(s) suppressed, each with a recorded reason:</p><ul>${report.suppressed
        .map(
          (entry) =>
            `<li><code>${escapeHtml(entry.finding.ruleId)}</code> ${escapeHtml(entry.finding.location.path)} — ${escapeHtml(entry.kind)}: ${escapeHtml(entry.reason)}</li>`
        )
        .join('')}</ul>`
    );
  }
  if (report.stats.findingsBelowThreshold > 0) {
    parts.push(
      `<p>${report.stats.findingsBelowThreshold} finding(s) below the reporting threshold were not listed.</p>`
    );
  }
  if (report.suppressionErrors.length > 0) {
    parts.push(
      `<p>${report.suppressionErrors.length} suppression directive(s) were ignored:</p><ul>${report.suppressionErrors
        .map(
          (error) =>
            `<li><code>${escapeHtml(error.path)}:${error.line}</code> ${escapeHtml(error.message)}</li>`
        )
        .join('')}</ul>`
    );
  }
  if (report.ruleErrors.length > 0) {
    parts.push(
      `<p>${report.ruleErrors.length} rule error(s):</p><ul>${report.ruleErrors
        .map(
          (error) =>
            `<li><code>${escapeHtml(error.ruleId)}</code> on <code>${escapeHtml(error.path)}</code>: ${escapeHtml(error.message)}</li>`
        )
        .join('')}</ul>`
    );
  }

  parts.push(
    `<p class="threshold">${
      report.exceedsFailOn
        ? `At least one finding meets the failure threshold (${escapeHtml(report.failOn)}).`
        : `No finding meets the failure threshold (${escapeHtml(report.failOn)}).`
    }</p>`
  );

  return parts.join('\n');
}

/**
 * Escapes every character that can change the meaning of surrounding markup.
 *
 * Quotes included: interpolations appear inside attributes as well as in text,
 * and an unescaped quote there is an attribute injection.
 */
export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const STYLES = `
:root { color-scheme: light dark; --bg: #ffffff; --fg: #1a1a1a; --muted: #666; --line: #e0e0e0; --card: #fafafa; }
@media (prefers-color-scheme: dark) { :root { --bg: #16181d; --fg: #e8e8e8; --muted: #9aa0a6; --line: #2c2f36; --card: #1d2026; } }
* { box-sizing: border-box; }
body { margin: 0 auto; padding: 2rem 1.25rem 4rem; max-width: 60rem; background: var(--bg); color: var(--fg);
  font: 15px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
h2 { font-size: 1.1rem; margin: 0 0 .5rem; }
h3 { font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); margin: 1rem 0 .25rem; }
p { margin: .4rem 0; }
code { font: 13px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; background: var(--card); padding: .1rem .3rem; border-radius: 3px; word-break: break-word; }
pre { background: var(--card); border: 1px solid var(--line); border-radius: 6px; padding: .75rem; overflow-x: auto; }
pre code { background: none; padding: 0; }
.meta, .fingerprint { color: var(--muted); font-size: .85rem; }
.warning { border-left: 3px solid #d97706; background: var(--card); padding: .6rem .8rem; font-weight: 600; }
.summary { display: flex; flex-wrap: wrap; gap: .5rem; margin: 1.25rem 0; }
.count { flex: 1 1 6rem; border: 1px solid var(--line); border-radius: 6px; padding: .6rem .75rem; background: var(--card); }
.count .n { display: block; font-size: 1.5rem; font-weight: 700; }
.count .s { color: var(--muted); font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; }
.count.critical .n, .count.high .n { color: #dc2626; }
.count.medium .n { color: #d97706; }
.finding { border: 1px solid var(--line); border-left-width: 4px; border-radius: 6px; padding: 1rem 1.1rem; margin: 1rem 0; background: var(--card); }
.finding.critical, .finding.high { border-left-color: #dc2626; }
.finding.medium { border-left-color: #d97706; }
.finding.low { border-left-color: #2563eb; }
.finding.info { border-left-color: var(--muted); }
.tags { display: flex; flex-wrap: wrap; gap: .4rem; align-items: center; }
.tag { font-size: .75rem; text-transform: uppercase; letter-spacing: .04em; border: 1px solid var(--line); border-radius: 999px; padding: .1rem .5rem; color: var(--muted); }
.adjustment { color: var(--muted); font-size: .9rem; }
ul { margin: .3rem 0; padding-left: 1.1rem; }
.empty { color: var(--muted); }
footer { border-top: 1px solid var(--line); margin-top: 2rem; padding-top: 1rem; color: var(--muted); font-size: .9rem; }
.threshold { font-weight: 600; color: var(--fg); }
`;
