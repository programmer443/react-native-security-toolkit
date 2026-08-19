import fs from 'node:fs/promises';
import path from 'node:path';

import { deduplicateFindings } from './dedupe.js';
import { createFingerprint } from './fingerprint.js';
import { mapBounded } from './pool.js';
import { RuleRegistry, builtinRules } from './ruleRegistry.js';
import { compareSeverity, meetsThreshold, resolveSeverity } from './severity.js';
import { SuppressionIndex, scanInlineDirectives } from './suppression.js';
import { discoverFiles } from '../discovery/discoverFiles.js';
import { knowledge } from '../knowledge/index.js';
import { looksBinary } from '../discovery/binary.js';
import { defaultConfig } from '../config/defaults.js';
import { isParsableLanguage, parseJavaScript } from '../parsers/javascript.js';
import type { AuditorConfig } from '../types/config.js';
import type { DiscoveredFile, SkippedPath } from '../types/file.js';
import type { RawFinding, SecurityFinding } from '../types/finding.js';
import type {
  AuditReport,
  RuleError,
  SuppressedFindingReport,
  SuppressionErrorReport,
} from '../types/report.js';
import type { ParsedFile } from '../types/parse.js';
import type { ProjectContext, RuleContext, SecurityRule } from '../types/rule.js';

/**
 * Scanning a project, end to end.
 *
 * The order of operations is the design:
 *
 * ```text
 *   discover (hostile-safe)  →  classify  →  read  →  parse once
 *        →  run every applicable rule against the shared parse
 *        →  fingerprint  →  deduplicate  →  suppress  →  threshold  →  report
 * ```
 *
 * Two commitments shape the whole function. **Target code is never executed**
 * (§44/§71): files are read, parsed and inspected, and nothing in this package
 * imports, requires, evaluates or spawns anything from the project under
 * analysis. And **nothing partial is reported as complete**: every limit, skip,
 * rule failure and malformed suppression appears in the result, because a
 * scanner that hides its own gaps produces a clean report for a project it
 * barely read.
 */

export interface AuditOptions {
  /** Project root to scan. */
  readonly root: string;
  /** Resolved configuration. Defaults are used when omitted. */
  readonly config?: AuditorConfig;
  /**
   * Rules to run.
   *
   * Defaults to the built-in set, which is empty until Phase 6. Passing rules
   * explicitly is how the engine is tested, and how a project can run its own.
   */
  readonly rules?: readonly SecurityRule[];
  /** Injectable clock, so tests can assert on the wall-clock budget. */
  readonly now?: () => number;
}

export async function auditProject(options: AuditOptions): Promise<AuditReport> {
  const config = options.config ?? defaultConfig();
  const now = options.now ?? (() => Date.now());
  const registry =
    options.rules === undefined
      ? new RuleRegistry([...builtinRules])
      : new RuleRegistry([...options.rules]);

  const root = path.resolve(options.root);
  const startedAtMs = now();
  const startedAt = new Date().toISOString();
  const deadline = startedAtMs + config.limits.timeoutMs;

  const discovery = await discoverFiles({
    root,
    include: config.include,
    exclude: config.exclude,
    limits: config.limits,
  });

  const project: ProjectContext = {
    files: discovery.files.map((file) => file.path),
    ...(await readPackageJson(root)),
  };

  const suppressions = new SuppressionIndex(config);
  const skipped: SkippedPath[] = [...discovery.skipped];
  const ruleErrors: RuleError[] = [];
  const suppressionErrors: SuppressionErrorReport[] = [];
  const rawFindings: Array<{ file: DiscoveredFile; rule: SecurityRule; finding: RawFinding }> = [];

  let bytesRead = 0;
  let filesParsed = 0;
  let filesAnalysed = 0;

  const scan = await mapBounded(
    discovery.files,
    async (file) => {
      const rules = registry.rulesFor(file, config.disabledRules);
      if (rules.length === 0) {
        // Not analysed, and not counted as analysed. A file no rule applies to
        // has not been examined, and a coverage number that says otherwise is
        // the kind of quiet overclaim this package exists to avoid.
        return;
      }

      let buffer: Buffer;
      try {
        buffer = await fs.readFile(file.absolutePath);
      } catch (error: unknown) {
        skipped.push({
          path: file.path,
          reason: 'unreadable',
          detail: error instanceof Error ? error.message : String(error),
        });
        return;
      }

      // Extension-based binary detection happens in discovery; this catches a
      // dylib named `helpers.ts`, which is not a hypothetical in a repository
      // that wants to be misread.
      if (looksBinary(buffer)) {
        skipped.push({ path: file.path, reason: 'binary', detail: 'binary content' });
        return;
      }

      bytesRead += buffer.byteLength;
      const text = buffer.toString('utf8');
      const lines = text.split(/\r?\n/);

      const inline = scanInlineDirectives(file.path, lines);
      suppressions.addFileDirectives(file.path, inline.directives);
      suppressionErrors.push(...inline.errors);

      // One parse per file, shared by every rule that wants it (§45): parsing is
      // the expensive step, and doing it per rule is how a scanner ends up
      // quadratic in rule count.
      let parsed: ParsedFile | undefined;
      if (isParsableLanguage(file.language)) {
        parsed = parseJavaScript(text, {
          language: file.language,
          maxBytes: config.limits.maxParseBytes,
        });
        if (parsed.kind === 'javascript') {
          filesParsed += 1;
        }
      }

      const context: RuleContext = {
        file,
        text,
        lines,
        project,
        ...(parsed === undefined ? {} : { parsed }),
      };

      filesAnalysed += 1;

      for (const rule of rules) {
        try {
          const produced = await rule.detect(context);
          for (const finding of produced) {
            rawFindings.push({ file, rule, finding });
          }
        } catch (error: unknown) {
          // A rule that throws is a bug in the rule, not a verdict about the
          // file. It is reported and the scan continues; one broken rule must
          // not cost a project its whole audit.
          ruleErrors.push({
            ruleId: rule.id,
            path: file.path,
            message: error instanceof Error ? error.message : String(error),
          });
        }
      }
    },
    {
      concurrency: config.limits.concurrency,
      shouldStop: () => now() >= deadline,
    }
  );

  const finalised = rawFindings.map(({ file, rule, finding }) =>
    finalise(finding, file, rule, config)
  );
  const deduplicated = deduplicateFindings(finalised);

  const suppressed: SuppressedFindingReport[] = [];
  const surviving: SecurityFinding[] = [];
  for (const finding of deduplicated) {
    const suppression = suppressions.suppressionFor(finding);
    if (suppression === undefined) {
      surviving.push(finding);
    } else {
      suppressed.push({ finding, kind: suppression.kind, reason: suppression.reason });
    }
  }

  const reported = surviving.filter((finding) =>
    meetsThreshold(finding.severity, config.minimumSeverity)
  );
  const belowThreshold = surviving.length - reported.length;

  reported.sort((left, right) => {
    const bySeverity = compareSeverity(right.severity, left.severity);
    if (bySeverity !== 0) {
      return bySeverity;
    }
    if (left.location.path !== right.location.path) {
      return left.location.path < right.location.path ? -1 : 1;
    }
    return (left.location.line ?? 0) - (right.location.line ?? 0);
  });

  return {
    startedAt,
    durationMs: Math.max(0, now() - startedAtMs),
    root,
    findings: reported,
    suppressed,
    skipped,
    ruleErrors,
    suppressionErrors,
    stats: {
      filesDiscovered: discovery.files.length,
      filesAnalysed,
      filesParsed,
      bytesRead,
      rulesRun: registry.rules.length,
      findingsBeforeDeduplication: finalised.length,
      findingsSuppressed: suppressed.length,
      findingsBelowThreshold: belowThreshold,
      excludedByConfig: discovery.excludedCount,
      notIncludedByConfig: discovery.notIncludedCount,
    },
    truncated: discovery.truncated,
    timedOut: scan.stopped,
    failOn: config.failOn,
    exceedsFailOn: reported.some((finding) => meetsThreshold(finding.severity, config.failOn)),
    aiUsed: false,
  };
}

/** Adds identity, context-adjusted severity and provenance to a rule's raw finding. */
function finalise(
  raw: RawFinding,
  file: DiscoveredFile,
  rule: SecurityRule,
  config: AuditorConfig
): SecurityFinding {
  // `structuralContext` is fingerprint input, not part of the reported finding,
  // so it is separated from the fields that are carried through.
  const { structuralContext, ...rest } = raw;

  const fingerprint = createFingerprint({
    ruleId: rule.id,
    path: file.path,
    evidence: raw.evidence.map((entry) => entry.snippet ?? entry.description),
    ...(structuralContext === undefined ? {} : { structuralContext }),
  });

  const severity = resolveSeverity(raw.severity, file.path, rule.id, config.ruleOverrides);

  // Standards references are resolved from the knowledge snapshot, never from
  // the rule's own prose: a finding may narrow the rule's mapping, but it cannot
  // invent one, and the titles come from the standard itself.
  const { knowledge: findingRefs, ...carried } = rest;
  const references = knowledge.resolve(findingRefs ?? rule.knowledge);

  return {
    ...carried,
    ...references,
    id: `${rule.id}-${fingerprint.slice(0, 12)}`,
    ruleId: rule.id,
    severity: severity.severity,
    sources: raw.sources ?? ['deterministic'],
    fingerprint,
    // The path a rule reported is trusted for content but not for shape: a
    // report must never contain an absolute path from the scanning machine.
    location: { ...raw.location, path: file.path },
    ...(severity.adjustment === undefined ? {} : { severityAdjustment: severity.adjustment }),
  };
}

/**
 * Reads the project's own `package.json`, if it has a valid one.
 *
 * Parsed with `JSON.parse` and nothing else. The manifest of a hostile
 * repository is data, and the moment it is `require`d it becomes code.
 */
async function readPackageJson(
  root: string
): Promise<{ packageJson?: Readonly<Record<string, unknown>> }> {
  try {
    const text = await fs.readFile(path.join(root, 'package.json'), 'utf8');
    const parsed: unknown = JSON.parse(text);
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
      return { packageJson: parsed as Record<string, unknown> };
    }
  } catch {
    // A project without a readable package.json is perfectly scannable.
  }
  return {};
}
