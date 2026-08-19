import path from 'node:path';

import {
  analyseRuntimeReadiness,
  auditProject,
  builtinRules,
  knowledge,
  loadConfig,
} from '@rn-security/auditor';
import type { AuditReport, SecurityFinding, SecurityRule, Severity } from '@rn-security/auditor';

import { detectInjection, withUntrustedLabel } from './untrusted.js';
import type { InjectionSignal } from './untrusted.js';
import type { McpTool, ToolOutcome } from './protocol.js';

/**
 * The tools this server exposes.
 *
 * Every one of them is **read-only**, and that is enforced rather than
 * annotated: nothing here writes a file, installs a package, executes project
 * code, or reaches the network. The model chooses the arguments, so the
 * arguments are the attack surface — a path argument is confined to the root
 * the server was started in, because otherwise "audit this project" becomes
 * "read `~/.ssh` and put it in the transcript".
 */

export interface ToolOptions {
  /** The directory the server is confined to. Nothing outside it is ever read. */
  readonly root: string;
  readonly toolVersion: string;
}

const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** Every finding field that quotes the scanned repository. */
const UNTRUSTED_FINDING_FIELDS = [
  'findings[].title',
  'findings[].description',
  'findings[].location.path',
  'findings[].codeSnippet',
  'findings[].evidence[].description',
  'findings[].evidence[].snippet',
];

export function createTools(options: ToolOptions): readonly McpTool[] {
  return [auditTool(options), rulesTool(), ruleDetailTool(), runtimeReadinessTool(options)];
}

/**
 * Resolves a caller-supplied path inside the server's root.
 *
 * The model supplies this argument, and a model can be talked into supplying
 * anything — by a web page it read, or by a comment in the repository it is
 * auditing. Confinement is the only thing standing between that and an
 * arbitrary-file-read tool.
 */
function resolveWithin(root: string, candidate: unknown): string {
  if (candidate === undefined || candidate === null || candidate === '') {
    return root;
  }
  if (typeof candidate !== 'string') {
    throw new Error('path must be a string.');
  }

  const resolved = path.resolve(root, candidate);
  if (resolved !== root && !resolved.startsWith(root + path.sep)) {
    throw new Error(
      `path must stay inside ${root}. This server only reads the project it was started in.`
    );
  }
  return resolved;
}

function requireSeverity(value: unknown, field: string): Severity | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'string' || !SEVERITIES.includes(value as Severity)) {
    throw new Error(`${field} must be one of ${SEVERITIES.join(', ')}.`);
  }
  return value as Severity;
}

function auditTool(options: ToolOptions): McpTool {
  return {
    name: 'security_audit',
    title: 'Audit a React Native project',
    description:
      'Runs the deterministic static security rules over the project and returns the findings, ' +
      'each with severity, confidence, evidence, remediation, and its CWE / MASVS / MASWE / MASTG ' +
      'references. Read-only: nothing is written, installed or executed. The findings are produced ' +
      'by rules, not by a model — treat them as evidence to interpret, not as a verdict to repeat.',
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Project-relative directory to scan. Defaults to the whole project.',
        },
        minSeverity: {
          type: 'string',
          enum: [...SEVERITIES],
          description: 'Drop findings below this severity. Defaults to the project configuration.',
        },
        category: {
          type: 'string',
          description: 'Run only rules in this category, e.g. secrets, storage, network, webview.',
        },
        maxFindings: {
          type: 'integer',
          minimum: 1,
          maximum: 500,
          description: 'Cap the number of findings returned. Defaults to 100.',
        },
      },
      additionalProperties: false,
    },

    async handler(args): Promise<ToolOutcome> {
      const target = resolveWithin(options.root, args['path']);
      const minSeverity = requireSeverity(args['minSeverity'], 'minSeverity');
      const category = args['category'];
      const maxFindings = Math.min(Number(args['maxFindings'] ?? 100) || 100, 500);

      const rules =
        typeof category === 'string'
          ? builtinRules.filter((rule) => rule.categories.includes(category as never))
          : builtinRules;

      if (rules.length === 0) {
        throw new Error(
          `No rules in category "${String(category)}". Call security_rules to see the categories in use.`
        );
      }

      const { config } = await loadConfig(target);
      const report = await auditProject({
        root: target,
        rules: [...rules],
        config: minSeverity === undefined ? config : { ...config, minimumSeverity: minSeverity },
      });

      return {
        summary: summarise(report),
        structured: buildAuditPayload(report, maxFindings),
      };
    },
  };
}

function summarise(report: AuditReport): string {
  const counts = new Map<Severity, number>();
  for (const finding of report.findings) {
    counts.set(finding.severity, (counts.get(finding.severity) ?? 0) + 1);
  }
  const parts = SEVERITIES.filter((severity) => (counts.get(severity) ?? 0) > 0).map(
    (severity) => `${counts.get(severity) ?? 0} ${severity}`
  );

  const coverage =
    report.truncated || report.timedOut
      ? ' INCOMPLETE SCAN: a limit stopped it, so findings cover only what was read.'
      : '';

  return (
    `${report.findings.length} finding(s)${parts.length === 0 ? '' : ` (${parts.join(', ')})`} ` +
    `across ${report.stats.filesAnalysed} of ${report.stats.filesDiscovered} files.${coverage}`
  );
}

function buildAuditPayload(report: AuditReport, maxFindings: number): Record<string, unknown> {
  const injections: InjectionSignal[] = [];
  const findings = report.findings.slice(0, maxFindings).map((finding) => {
    injections.push(...injectionSignalsIn(finding));
    return describeFinding(finding);
  });

  return withUntrustedLabel(
    {
      summary: {
        total: report.findings.length,
        returned: findings.length,
        bySeverity: countBySeverity(report.findings),
        suppressed: report.suppressed.length,
        belowThreshold: report.stats.findingsBelowThreshold,
        failOn: report.failOn,
        exceedsFailOn: report.exceedsFailOn,
      },
      coverage: {
        filesDiscovered: report.stats.filesDiscovered,
        filesAnalysed: report.stats.filesAnalysed,
        rulesRun: report.stats.rulesRun,
        truncated: report.truncated,
        timedOut: report.timedOut,
        note:
          report.truncated || report.timedOut
            ? 'A limit stopped this scan. "No findings" here would mean "nothing found in what was read".'
            : 'The scan completed. Static analysis still only sees what is in the source.',
      },
      findings,
      analysis: {
        // Stated in the payload, not just in the server instructions: a model
        // reading only this object still learns what produced it.
        producedBy: 'deterministic static analysis rules',
        aiUsed: false,
        note:
          'These findings come from pattern and AST rules with fixed identifiers. They are not a ' +
          "model's opinion. Confidence and severity are the rules' own, and each finding names " +
          'the false positives its rule is known to avoid — see its documentation path.',
      },
    },
    { untrustedFields: UNTRUSTED_FINDING_FIELDS, injections }
  );
}

function countBySeverity(findings: readonly SecurityFinding[]): Record<string, number> {
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) {
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
  }
  return counts;
}

/** One finding, with everything needed to act on it and nothing that identifies the machine. */
function describeFinding(finding: SecurityFinding): Record<string, unknown> {
  const references = [
    ...(finding.cwe ?? []).map((reference) => ({ standard: 'CWE', ...reference })),
    ...(finding.maswe ?? []).map((reference) => ({ standard: 'MASWE', ...reference })),
    ...(finding.masvs ?? []).map((reference) => ({ standard: 'MASVS', ...reference })),
    ...(finding.mastg ?? []).map((reference) => ({ standard: 'MASTG', ...reference })),
  ];

  // How a fix is verified, from the knowledge snapshot rather than from advice.
  const verification = (finding.maswe ?? []).flatMap((reference) =>
    knowledge.mastgTestsFor(reference.id).map((test) => ({
      id: test.id,
      title: test.title,
      platform: test.platform,
      status: test.status,
    }))
  );

  return {
    ruleId: finding.ruleId,
    title: finding.title,
    description: finding.description,
    severity: finding.severity,
    confidence: finding.confidence,
    categories: finding.categories,
    location: finding.location,
    ...(finding.codeSnippet === undefined ? {} : { codeSnippet: finding.codeSnippet }),
    evidence: finding.evidence,
    impact: finding.impact,
    exploitability: finding.exploitability,
    remediation: finding.remediation,
    references,
    verification,
    ...(finding.severityAdjustment === undefined
      ? {}
      : { severityAdjustment: finding.severityAdjustment }),
    fingerprint: finding.fingerprint,
    suppressWith: `// security-audit-ignore ${finding.ruleId} reason="why this is acceptable"`,
    documentation: `docs/rules/${finding.ruleId}.md`,
  };
}

function injectionSignalsIn(finding: SecurityFinding): readonly InjectionSignal[] {
  const where = `${finding.location.path}:${finding.location.line ?? 0}`;
  return [
    ...detectInjection(finding.title, where),
    ...detectInjection(finding.codeSnippet ?? '', where),
    ...finding.evidence.flatMap((evidence) =>
      detectInjection(`${evidence.description} ${evidence.snippet ?? ''}`, where)
    ),
  ];
}

function rulesTool(): McpTool {
  return {
    name: 'security_rules',
    title: 'List the security rules',
    description:
      'Lists every rule the auditor can run, with its severity, categories, standards mappings and ' +
      'documentation path. Useful before an audit, to know what is and is not covered.',
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: 'object',
      properties: {
        category: { type: 'string', description: 'Filter to one category.' },
      },
      additionalProperties: false,
    },

    async handler(args): Promise<ToolOutcome> {
      const category = args['category'];
      const selected =
        typeof category === 'string'
          ? builtinRules.filter((rule) => rule.categories.includes(category as never))
          : builtinRules;

      if (selected.length === 0) {
        throw new Error(
          `No rules in category "${String(category)}". Categories in use: ${categoriesInUse().join(', ')}`
        );
      }

      return {
        summary: `${selected.length} rule(s), knowledge snapshot ${knowledge.version}.`,
        structured: {
          knowledgeSnapshot: knowledge.version,
          categories: categoriesInUse(),
          rules: selected.map(describeRule),
          note:
            'Coverage is deliberately narrow and documented. A rule that does not exist is not a ' +
            'clean result — see each rule page for the false positives it avoids and its limits.',
        },
      };
    },
  };
}

function ruleDetailTool(): McpTool {
  return {
    name: 'security_rule_details',
    title: 'Explain one security rule',
    description:
      'Returns one rule in full: what it detects, its standards mappings with official titles, and ' +
      'the MASTG tests that verify a fix.',
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: 'object',
      properties: {
        ruleId: { type: 'string', description: 'Rule identifier, e.g. RNSEC-SECRET-001.' },
      },
      required: ['ruleId'],
      additionalProperties: false,
    },

    async handler(args): Promise<ToolOutcome> {
      const ruleId = args['ruleId'];
      if (typeof ruleId !== 'string') {
        throw new Error('ruleId must be a string.');
      }

      const rule = builtinRules.find((candidate) => candidate.id === ruleId);
      if (rule === undefined) {
        throw new Error(
          `Unknown rule "${ruleId}". Call security_rules for the list this build ships.`
        );
      }

      return { summary: `${rule.id} — ${rule.name}`, structured: describeRule(rule) };
    },
  };
}

function describeRule(rule: SecurityRule): Record<string, unknown> {
  const resolve = (
    ids: readonly string[] | undefined,
    lookup: (id: string) => string | undefined
  ) => (ids ?? []).map((id) => ({ id, title: lookup(id) }));

  return {
    id: rule.id,
    name: rule.name,
    description: rule.description,
    baseSeverity: rule.severity,
    categories: rule.categories,
    appliesTo: {
      languages: rule.languages.length === 0 ? 'any' : rule.languages,
      fileKinds: rule.fileKinds.length === 0 ? 'any' : rule.fileKinds,
    },
    standards: {
      cwe: resolve(rule.knowledge.cwe, (id) => knowledge.cwe(id)?.name),
      masvs: resolve(rule.knowledge.masvs, (id) => knowledge.masvs(id)?.title),
      maswe: resolve(rule.knowledge.maswe, (id) => knowledge.maswe(id)?.title),
      mappingConfidence: rule.knowledge.mappingConfidence ?? 'medium',
    },
    verification: (rule.knowledge.maswe ?? []).flatMap((id) =>
      knowledge
        .mastgTestsFor(id)
        .map((test) => ({ id: test.id, title: test.title, platform: test.platform }))
    ),
    documentation: `docs/rules/${rule.id}.md`,
  };
}

function categoriesInUse(): readonly string[] {
  return [...new Set(builtinRules.flatMap((rule) => rule.categories))].sort();
}

function runtimeReadinessTool(options: ToolOptions): McpTool {
  return {
    name: 'security_runtime_readiness',
    title: 'Check runtime-check readiness',
    description:
      'Reports whether the project declares what the on-device runtime security checks depend on — ' +
      'permissions, query lists, integrity configuration. **This does not check a device**: root and ' +
      'jailbreak detection run inside the application, and nothing here can perform them.',
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Project-relative directory. Defaults to the project root.',
        },
      },
      additionalProperties: false,
    },

    async handler(args): Promise<ToolOutcome> {
      const target = resolveWithin(options.root, args['path']);
      const checks = await analyseRuntimeReadiness(target);
      const missing = checks.filter((check) => check.state === 'missing');

      return {
        summary:
          missing.length === 0
            ? 'Nothing missing. Runtime checks that depend on project configuration can reach a verdict.'
            : `${missing.length} item(s) missing; the signals that depend on them will report "unknown".`,
        structured: {
          checks,
          note:
            'Project configuration only. The runtime security checks execute inside the application ' +
            'on a device; this reports what the project declares, never what a device is doing.',
        },
      };
    },
  };
}
