import { consoleReporter } from '../console.js';
import { getReporter, reportFormats, reporters } from '../index.js';
import { htmlReporter } from '../html.js';
import { jsonReporter } from '../json.js';
import { markdownReporter } from '../markdown.js';
import { sarifReporter } from '../sarif.js';
import { hostileReport, sampleReport } from './helpers/sampleReport.js';

describe('reporter registry', () => {
  it('offers every documented format', () => {
    expect([...reportFormats].sort()).toEqual(['console', 'html', 'json', 'markdown', 'sarif']);
  });

  it('names an unknown format instead of silently producing nothing', () => {
    expect(() => getReporter('pdf')).toThrow(/Unknown report format "pdf"/);
    expect(() => getReporter('pdf')).toThrow(/console, json, markdown, html, sarif/);
  });

  it('gives every reporter an extension and a media type', () => {
    for (const reporter of Object.values(reporters)) {
      expect(reporter.extension).toMatch(/^[a-z]+$/);
      expect(reporter.contentType).toContain('/');
    }
  });

  it('renders every format from one report, without re-running the scan', () => {
    const report = sampleReport();

    for (const reporter of Object.values(reporters)) {
      expect(reporter.render(report).length).toBeGreaterThan(0);
    }
  });

  it('keeps the local root out of every format unless asked', () => {
    // A report travels into CI logs, pull requests and issue trackers.
    const report = sampleReport();

    for (const reporter of Object.values(reporters)) {
      expect(reporter.render(report)).not.toContain('/Users/example/work/app');
    }
  });

  it('states an incomplete scan in every format', () => {
    // "No findings" from a truncated scan means something different, and a
    // reader cannot tell unless every format says so.
    const report = sampleReport({ findings: [], suppressed: [], truncated: true });

    for (const reporter of Object.values(reporters)) {
      expect(reporter.render(report)).toMatch(/INCOMPLETE SCAN|truncated/i);
    }
  });
});

describe('console reporter', () => {
  it('reports findings with the reasoning attached', () => {
    const output = consoleReporter.render(sampleReport());

    expect(output).toContain('CRITICAL');
    expect(output).toContain('RNSEC-SECRET-001');
    expect(output).toContain('src/api/client.ts:12');
    expect(output).toContain('confidence: very-high');
    expect(output).toContain('standards: CWE-798, MASWE-0004, MASVS-STORAGE-1');
    expect(output).toContain('fingerprint: 9f2c1a8b4d3e5f60718293a4b5c6d7e8');
  });

  it('explains a severity adjustment rather than applying it silently', () => {
    expect(consoleReporter.render(sampleReport())).toContain(
      'severity adjusted from high: file is test code'
    );
  });

  it('summarises suppressions, thresholds and the failure verdict', () => {
    const output = consoleReporter.render(sampleReport());

    expect(output).toContain('Summary: 1 critical, 1 medium');
    expect(output).toContain('1 finding(s) suppressed');
    expect(output).toContain('2 finding(s) below the reporting threshold');
    expect(output).toContain('At least one finding meets the failure threshold (high).');
  });

  it('emits no escape codes unless colour was asked for', () => {
    // Piping a report into a file and finding it full of escape codes is the
    // kind of small thing that makes a tool feel careless.
    expect(consoleReporter.render(sampleReport())).not.toContain('[');
    expect(consoleReporter.render(sampleReport(), { colour: true })).toContain('[');
  });

  it('says so plainly when there is nothing to report', () => {
    const output = consoleReporter.render(
      sampleReport({ findings: [], suppressed: [], exceedsFailOn: false })
    );

    expect(output).toContain('No findings.');
    expect(output).toContain('No finding meets the failure threshold');
  });
});

describe('JSON reporter', () => {
  function parse(report = sampleReport(), options = {}): Record<string, unknown> {
    return JSON.parse(jsonReporter.render(report, options)) as Record<string, unknown>;
  }

  it('produces a versioned envelope', () => {
    const payload = parse();

    expect(payload['schemaVersion']).toBe('1.0');
    expect((payload['tool'] as Record<string, unknown>)['name']).toBe('rn-security-auditor');
    expect((payload['tool'] as Record<string, unknown>)['knowledgeSnapshot']).toMatch(
      /^\d{4}\.\d+$/
    );
  });

  it('carries the counts a dashboard needs without recomputing them', () => {
    const summary = parse()['summary'] as Record<string, unknown>;

    expect(summary['total']).toBe(2);
    expect(summary['bySeverity']).toEqual({ critical: 1, high: 0, medium: 1, low: 0, info: 0 });
    expect(summary['exceedsFailOn']).toBe(true);
  });

  it('states coverage and that no AI was involved', () => {
    const scan = parse()['scan'] as Record<string, unknown>;

    expect(scan).toMatchObject({ truncated: false, timedOut: false, aiUsed: false });
  });

  it('omits the root by default and includes it on request', () => {
    expect(parse()['root']).toBeUndefined();
    expect(parse(sampleReport(), { includeRoot: true })['root']).toBe('/Users/example/work/app');
  });

  it('is deterministic given a fixed clock', () => {
    const options = { now: () => new Date('2026-08-19T10:00:00.000Z') };

    expect(jsonReporter.render(sampleReport(), options)).toBe(
      jsonReporter.render(sampleReport(), options)
    );
  });
});

describe('markdown reporter', () => {
  it('groups findings by severity under a summary table', () => {
    const output = markdownReporter.render(sampleReport());

    expect(output).toContain('| Severity | Findings |');
    expect(output).toContain('## Critical');
    expect(output).toContain('## Medium');
  });

  it('warns about an incomplete scan in a way GitHub renders', () => {
    const output = markdownReporter.render(sampleReport({ truncated: true }));

    expect(output).toContain('> [!WARNING]');
  });

  it('escapes untrusted text so it cannot break out of a table cell or restyle the report', () => {
    // Titles, paths and snippets all come from the repository under analysis.
    const output = markdownReporter.render(hostileReport());

    expect(output).not.toContain('| breaking |');
    expect(output).toContain('\\|');
    expect(output).not.toMatch(/^```$[\s\S]*?```fences```/m);
  });

  it('publishes the fingerprint so a finding can be suppressed with a reason', () => {
    expect(markdownReporter.render(sampleReport())).toContain('9f2c1a8b4d3e5f60718293a4b5c6d7e8');
  });
});

describe('HTML reporter', () => {
  it('produces a self-contained document with no external resources', () => {
    const output = htmlReporter.render(sampleReport());

    expect(output.startsWith('<!doctype html>')).toBe(true);
    expect(output).toContain('<style>');
    // No network access, no CDN, nothing to load from a file:// URL.
    expect(output).not.toMatch(/<link\b|<img\b|src=|https?:\/\/(?!github)/i);
  });

  it('contains no script at all', () => {
    // A report is opened in a browser, often from a CI artefact. There is no
    // reason for it to execute anything.
    const output = htmlReporter.render(sampleReport());

    expect(output.toLowerCase()).not.toContain('<script');
    expect(output.toLowerCase()).not.toContain('onerror=');
  });

  it('escapes hostile content instead of rendering it', () => {
    const output = htmlReporter.render(hostileReport());

    expect(output).not.toContain('<script>alert(document.cookie)</script>');
    expect(output).toContain('&lt;script&gt;alert(document.cookie)&lt;/script&gt;');
    // An unescaped quote inside an attribute is an attribute injection.
    expect(output).not.toContain('" onmouseover="alert(1)');
    expect(output).not.toContain('</code></pre><script>');
  });

  it('shows the evidence and the standards behind each finding', () => {
    const output = htmlReporter.render(sampleReport());

    expect(output).toContain('Matched the AWS access key id format');
    expect(output).toContain('CWE-798');
    expect(output).toContain('Use of Hard-coded Credentials');
    expect(output).toContain('high confidence mapping');
  });

  it('lists what was suppressed and why', () => {
    expect(htmlReporter.render(sampleReport())).toContain(
      'illustration in rule documentation, not a live key'
    );
  });
});

describe('all formats agree', () => {
  it('report the same number of findings', () => {
    const report = sampleReport();
    const json = JSON.parse(jsonReporter.render(report)) as { summary: { total: number } };
    const sarif = JSON.parse(sarifReporter.render(report)) as {
      runs: Array<{ results: Array<{ suppressions?: unknown }> }>;
    };
    const unsuppressed = (sarif.runs[0]?.results ?? []).filter(
      (result) => result.suppressions === undefined
    );

    expect(json.summary.total).toBe(report.findings.length);
    expect(unsuppressed).toHaveLength(report.findings.length);
  });
});
