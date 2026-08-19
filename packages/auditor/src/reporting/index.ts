import { consoleReporter } from './console.js';
import { htmlReporter } from './html.js';
import { jsonReporter } from './json.js';
import { markdownReporter } from './markdown.js';
import { sarifReporter } from './sarif.js';
import type { ReportFormat, Reporter } from './types.js';

/**
 * The report formats the auditor can produce.
 *
 * One report, several renderings — a scan is never re-run to change the output
 * format, which is what keeps a CI job that publishes SARIF *and* prints a
 * console summary honest: both describe the same run.
 */
export const reporters: Readonly<Record<ReportFormat, Reporter>> = {
  console: consoleReporter,
  json: jsonReporter,
  markdown: markdownReporter,
  html: htmlReporter,
  sarif: sarifReporter,
};

export const reportFormats: readonly ReportFormat[] = Object.keys(reporters) as ReportFormat[];

/** Looks up a reporter by name, or throws with the list of valid names. */
export function getReporter(format: string): Reporter {
  const reporter = reporters[format as ReportFormat];
  if (reporter === undefined) {
    throw new Error(
      `Unknown report format "${format}". Valid formats: ${reportFormats.join(', ')}.`
    );
  }
  return reporter;
}

export { consoleReporter } from './console.js';
export { htmlReporter, escapeHtml } from './html.js';
export { jsonReporter } from './json.js';
export { markdownReporter } from './markdown.js';
export { sarifReporter } from './sarif.js';
export { countBySeverity, coverageWarning } from './types.js';
export type { ReportFormat, ReportOptions, Reporter } from './types.js';
