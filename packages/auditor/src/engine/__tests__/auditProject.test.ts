import { auditProject } from '../auditProject.js';
import { defaultConfig } from '../../config/defaults.js';
import { TempProject } from '../../__tests__/helpers/tempProject.js';
import type { AuditorConfig } from '../../types/config.js';
import type { RawFinding } from '../../types/finding.js';
import type { RuleContext, SecurityRule } from '../../types/rule.js';

/**
 * A rule that reports every line containing a marker.
 *
 * The engine ships no rules until Phase 6, so the engine is tested with rules
 * written here. That is the point of the contract: a rule is a pure function of
 * its context, and one written in a test behaves exactly like one written in the
 * library.
 */
function markerRule(overrides: Partial<SecurityRule> = {}): SecurityRule {
  return {
    id: 'RNSEC-SECRET-001',
    name: 'Marker',
    description: 'Reports the marker string.',
    severity: 'high',
    categories: ['secrets'],
    languages: [],
    fileKinds: [],
    knowledge: { cwe: ['CWE-798'] },
    detect: (context: RuleContext): RawFinding[] =>
      context.lines.flatMap((line, index) =>
        line.includes('MARKER')
          ? [
              {
                ruleId: 'RNSEC-SECRET-001',
                title: 'Marker found',
                description: 'The marker string appears in this file.',
                severity: 'high' as const,
                confidence: 'high' as const,
                categories: ['secrets' as const],
                location: { path: context.file.path, line: index + 1 },
                evidence: [
                  { kind: 'matched-pattern', description: 'marker', snippet: line.trim() },
                ],
                impact: 'None. This is a test rule.',
                exploitability: 'None.',
                remediation: 'Remove the marker.',
              },
            ]
          : []
      ),
    ...overrides,
  };
}

function configWith(overrides: Partial<AuditorConfig> = {}): AuditorConfig {
  return { ...defaultConfig(), ...overrides };
}

describe('auditProject', () => {
  let project: TempProject;

  beforeEach(() => {
    project = TempProject.create();
  });

  afterEach(() => {
    project.remove();
  });

  it('reports findings with project-relative paths and a stable identity', async () => {
    project.file('src/api/client.ts', 'const key = "MARKER";\n');

    const report = await auditProject({ root: project.root, rules: [markerRule()] });

    expect(report.findings).toHaveLength(1);
    const finding = report.findings[0];
    expect(finding?.location).toEqual({ path: 'src/api/client.ts', line: 1 });
    expect(finding?.fingerprint).toMatch(/^[0-9a-f]{32}$/);
    expect(finding?.id.startsWith('RNSEC-SECRET-001-')).toBe(true);
    expect(finding?.sources).toEqual(['deterministic']);
    expect(report.exceedsFailOn).toBe(true);
  });

  it('produces an identical report when run twice', async () => {
    project.file('src/a.ts', 'const a = "MARKER";\n').file('src/b.ts', 'const b = "MARKER";\n');

    const first = await auditProject({ root: project.root, rules: [markerRule()] });
    const second = await auditProject({ root: project.root, rules: [markerRule()] });

    expect(first.findings.map((finding) => finding.fingerprint)).toEqual(
      second.findings.map((finding) => finding.fingerprint)
    );
  });

  it('parses each file once and shares the tree with every rule', async () => {
    project.file('src/a.ts', 'const a = "MARKER";\n');
    const seen: Array<string | undefined> = [];
    const observer = (id: string): SecurityRule =>
      markerRule({
        id,
        detect: (context) => {
          seen.push(context.parsed?.kind);
          return [];
        },
      });

    const report = await auditProject({
      root: project.root,
      rules: [observer('RNSEC-SECRET-001'), observer('RNSEC-SECRET-002')],
    });

    expect(seen).toEqual(['javascript', 'javascript']);
    expect(report.stats.filesParsed).toBe(1);
  });

  it('downgrades a finding in test code and records the adjustment', async () => {
    project.file('src/__tests__/client.test.ts', 'const key = "MARKER";\n');

    const report = await auditProject({ root: project.root, rules: [markerRule()] });

    expect(report.findings[0]?.severity).toBe('medium');
    expect(report.findings[0]?.severityAdjustment?.reason).toBe('file is test code');
  });

  it('drops findings below the configured reporting floor, and counts them', async () => {
    project.file('src/__fixtures__/sample.ts', 'const key = "MARKER";\n');

    const report = await auditProject({
      root: project.root,
      rules: [markerRule()],
      config: configWith({ minimumSeverity: 'medium' }),
    });

    expect(report.findings).toHaveLength(0);
    expect(report.stats.findingsBelowThreshold).toBe(1);
  });

  it('collapses duplicate findings from different rules into one', async () => {
    project.file('src/a.ts', 'const a = "MARKER";\n');

    // Two rules, same identifier is impossible, so the same rule reporting the
    // same evidence twice stands in for the pattern-plus-AST case.
    const doubleReporting = markerRule({
      detect: (context) => {
        const finding = markerRule().detect(context) as RawFinding[];
        return [...finding, ...finding];
      },
    });

    const report = await auditProject({ root: project.root, rules: [doubleReporting] });

    expect(report.stats.findingsBeforeDeduplication).toBe(2);
    expect(report.findings).toHaveLength(1);
  });

  it('applies inline suppressions and accounts for what they hid', async () => {
    project.file(
      'src/a.ts',
      [
        '// security-audit-ignore RNSEC-SECRET-001 reason="documented sample"',
        'const a = "MARKER";',
      ].join('\n')
    );

    const report = await auditProject({ root: project.root, rules: [markerRule()] });

    expect(report.findings).toHaveLength(0);
    expect(report.suppressed).toHaveLength(1);
    expect(report.suppressed[0]?.reason).toBe('documented sample');
  });

  it('reports a suppression with no reason instead of honouring it', async () => {
    project.file(
      'src/a.ts',
      ['// security-audit-ignore RNSEC-SECRET-001', 'const a = "MARKER";'].join('\n')
    );

    const report = await auditProject({ root: project.root, rules: [markerRule()] });

    expect(report.findings).toHaveLength(1);
    expect(report.suppressionErrors[0]?.line).toBe(1);
  });

  it('skips a disabled rule entirely', async () => {
    project.file('src/a.ts', 'const a = "MARKER";\n');

    const report = await auditProject({
      root: project.root,
      rules: [markerRule()],
      config: configWith({ disabledRules: ['RNSEC-SECRET-001'] }),
    });

    expect(report.findings).toHaveLength(0);
  });

  it('survives a rule that throws, and names it', async () => {
    // One broken rule must not cost a project its whole audit.
    project.file('src/a.ts', 'const a = "MARKER";\n');

    const report = await auditProject({
      root: project.root,
      rules: [
        markerRule({
          id: 'RNSEC-BROKEN-001',
          detect: () => {
            throw new Error('rule exploded');
          },
        }),
        markerRule(),
      ],
    });

    expect(report.ruleErrors).toEqual([
      { ruleId: 'RNSEC-BROKEN-001', path: 'src/a.ts', message: 'rule exploded' },
    ]);
    expect(report.findings).toHaveLength(1);
  });

  it('reports whether any finding meets the failure threshold, without exiting', async () => {
    project.file('src/a.ts', 'const a = "MARKER";\n');

    const report = await auditProject({
      root: project.root,
      rules: [markerRule()],
      config: configWith({ failOn: 'critical' }),
    });

    expect(report.findings).toHaveLength(1);
    expect(report.exceedsFailOn).toBe(false);
  });

  it('stops at the wall-clock budget and marks the report timed out', async () => {
    for (let index = 0; index < 20; index += 1) {
      project.file(`src/file${index}.ts`, 'const a = "MARKER";\n');
    }

    // A clock that jumps past the deadline on its third reading.
    let readings = 0;
    const now = (): number => {
      readings += 1;
      return readings > 3 ? 10_000_000 : 0;
    };

    const report = await auditProject({
      root: project.root,
      rules: [markerRule()],
      config: configWith({
        limits: { ...defaultConfig().limits, concurrency: 1, timeoutMs: 1_000 },
      }),
      now,
    });

    expect(report.timedOut).toBe(true);
    expect(report.stats.filesAnalysed).toBeLessThan(20);
  });

  it('always states that no AI contributed', async () => {
    const report = await auditProject({ root: project.root, rules: [] });

    expect(report.aiUsed).toBe(false);
  });

  it('runs with no rules and reports nothing rather than failing', async () => {
    project.file('src/a.ts', 'const a = "MARKER";\n');

    const report = await auditProject({ root: project.root, rules: [] });

    expect(report.findings).toHaveLength(0);
    expect(report.stats.rulesRun).toBe(0);
    expect(report.stats.filesDiscovered).toBe(1);
  });
});
