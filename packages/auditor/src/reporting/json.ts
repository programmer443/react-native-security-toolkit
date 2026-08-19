import { TOOL_NAME, countBySeverity, timestamp } from './types.js';
import { knowledge } from '../knowledge/index.js';
import type { ReportOptions, Reporter } from './types.js';
import type { AuditReport } from '../types/report.js';

/**
 * The machine-readable format, for anything that is not GitHub code scanning.
 *
 * Two decisions worth stating:
 *
 * **It has its own version.** `schemaVersion` is not the package version. A
 * consumer needs to know whether the *shape* changed, and tying that to a
 * release number means every patch release looks like a breaking change.
 *
 * **The absolute root is opt-in.** A report travels into CI logs, pull requests
 * and issue trackers. `/Users/someone/work/client-project` is noise at best.
 */

/** Bumped only when the output shape changes in a way a consumer would notice. */
const SCHEMA_VERSION = '1.0';

export const jsonReporter: Reporter = {
  name: 'json',
  extension: 'json',
  contentType: 'application/json; charset=utf-8',

  render(report: AuditReport, options?: ReportOptions): string {
    const payload = {
      schemaVersion: SCHEMA_VERSION,
      tool: {
        name: TOOL_NAME,
        version: options?.toolVersion ?? '0.0.0',
        knowledgeSnapshot: knowledge.version,
      },
      generatedAt: timestamp(options),
      ...(options?.includeRoot === true ? { root: report.root } : {}),
      scan: {
        startedAt: report.startedAt,
        durationMs: report.durationMs,
        // Coverage is part of the contract, not a diagnostic: "no findings"
        // from a truncated scan means something different.
        truncated: report.truncated,
        timedOut: report.timedOut,
        aiUsed: report.aiUsed,
      },
      summary: {
        total: report.findings.length,
        bySeverity: countBySeverity(report),
        suppressed: report.suppressed.length,
        belowThreshold: report.stats.findingsBelowThreshold,
        failOn: report.failOn,
        exceedsFailOn: report.exceedsFailOn,
      },
      stats: report.stats,
      findings: report.findings,
      suppressed: report.suppressed,
      skipped: report.skipped,
      ruleErrors: report.ruleErrors,
      suppressionErrors: report.suppressionErrors,
    };

    return `${JSON.stringify(payload, null, 2)}\n`;
  },
};
