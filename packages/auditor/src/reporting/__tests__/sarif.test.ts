import fs from 'node:fs';
import path from 'node:path';
// Named imports: ajv and ajv-formats are CommonJS, and a default import of a
// CJS module is the module object rather than the constructor under
// `moduleResolution: nodenext`.
import { Ajv } from 'ajv';
import { fullFormats } from 'ajv-formats/dist/formats.js';

import { sarifReporter } from '../sarif.js';
import { hostileReport, sampleReport } from './helpers/sampleReport.js';

/**
 * SARIF is validated against **the specification's own schema**, not against our
 * reading of it.
 *
 * The schema is committed under `fixtures/` so this runs offline and gives the
 * same answer in a year. A hand-written set of assertions would pass happily
 * while producing a file GitHub rejects — which is the failure mode that matters,
 * because a rejected upload is silent from the developer's side.
 */
const schema: object = JSON.parse(
  fs.readFileSync(
    path.join(process.cwd(), 'src/reporting/__tests__/fixtures/sarif-2.1.0.schema.json'),
    'utf8'
  )
);

// `strict: false` because the SARIF schema uses draft-07 constructs ajv's strict
// mode objects to; formats are registered so `uri` and `date-time` are actually
// checked rather than silently ignored.
const ajv = new Ajv({ strict: false, allErrors: true });
// Formats are registered explicitly so `uri`, `uri-reference` and `date-time`
// are actually checked rather than silently ignored — which is where the
// interesting SARIF failures live.
for (const [name, format] of Object.entries(fullFormats)) {
  ajv.addFormat(name, format);
}
const validate = ajv.compile(schema);

function parse(output: string): Record<string, unknown> {
  return JSON.parse(output) as Record<string, unknown>;
}

function expectValid(output: string): void {
  const document = parse(output);
  const valid = validate(document);
  if (!valid) {
    throw new Error(
      `SARIF output failed schema validation:\n${(validate.errors ?? [])
        .map((error) => `  ${error.instancePath} ${error.message ?? ''}`)
        .join('\n')}`
    );
  }
}

describe('SARIF reporter', () => {
  it('produces a document that validates against the SARIF 2.1.0 schema', () => {
    expectValid(sarifReporter.render(sampleReport()));
  });

  it('validates with no findings, which is the common case in CI', () => {
    expectValid(
      sarifReporter.render(sampleReport({ findings: [], suppressed: [], exceedsFailOn: false }))
    );
  });

  it('validates when the scan was incomplete and a rule failed', () => {
    expectValid(
      sarifReporter.render(
        sampleReport({
          truncated: true,
          timedOut: true,
          ruleErrors: [{ ruleId: 'RNSEC-SECRET-001', path: 'src/a.ts', message: 'boom' }],
        })
      )
    );
  });

  it('validates with hostile content in every string', () => {
    expectValid(sarifReporter.render(hostileReport()));
  });

  it('describes each rule once, however many findings it produced', () => {
    const document = parse(sarifReporter.render(sampleReport()));
    const run = (document['runs'] as Array<Record<string, unknown>>)[0] ?? {};
    const driver = (run['tool'] as Record<string, Record<string, unknown>>)['driver'] ?? {};
    const rules = driver['rules'] as Array<Record<string, unknown>>;

    expect(rules.map((rule) => rule['id'])).toEqual(['RNSEC-SECRET-001', 'RNSEC-LOG-001']);
  });

  it('carries the properties GitHub code scanning reads', () => {
    // Without `security-severity` every alert is shown as a warning, whatever
    // the report said; without the `security` tag they are not security alerts.
    const document = parse(sarifReporter.render(sampleReport()));
    const run = (document['runs'] as Array<Record<string, unknown>>)[0] ?? {};
    const driver = (run['tool'] as Record<string, Record<string, unknown>>)['driver'] ?? {};
    const rules = driver['rules'] as Array<Record<string, Record<string, unknown>>>;
    const first = rules[0]?.['properties'] ?? {};

    expect(first['security-severity']).toBe('9.3');
    expect(first['tags']).toContain('security');
    expect(first['tags']).toContain('CWE-798');
    expect(first['precision']).toBe('very-high');
  });

  it('maps severity to a SARIF level rather than inventing one', () => {
    const document = parse(sarifReporter.render(sampleReport()));
    const run = (document['runs'] as Array<Record<string, unknown>>)[0] ?? {};
    const results = run['results'] as Array<Record<string, unknown>>;

    expect(results[0]?.['level']).toBe('error'); // critical
    expect(results[1]?.['level']).toBe('warning'); // medium
  });

  it('carries the line-number-free fingerprint as a partial fingerprint', () => {
    // This is what lets an alert survive an edit above the finding.
    const document = parse(sarifReporter.render(sampleReport()));
    const run = (document['runs'] as Array<Record<string, unknown>>)[0] ?? {};
    const results = run['results'] as Array<Record<string, Record<string, unknown>>>;

    expect(results[0]?.['partialFingerprints']?.['rnsecFingerprint']).toBe(
      '9f2c1a8b4d3e5f60718293a4b5c6d7e8'
    );
  });

  it('reports suppressed findings as dismissed rather than dropping them', () => {
    const document = parse(sarifReporter.render(sampleReport()));
    const run = (document['runs'] as Array<Record<string, unknown>>)[0] ?? {};
    const results = run['results'] as Array<Record<string, unknown>>;
    const suppressed = results.find((result) => result['suppressions'] !== undefined);

    expect(suppressed).toBeDefined();
    expect((suppressed?.['suppressions'] as Array<Record<string, unknown>>)[0]).toEqual({
      kind: 'inSource',
      justification: 'illustration in rule documentation, not a live key',
    });
  });

  it('keeps paths relative and does not leak the local root by default', () => {
    const output = sarifReporter.render(sampleReport());
    const document = parse(output);
    const run = (document['runs'] as Array<Record<string, unknown>>)[0] ?? {};
    const results = run['results'] as Array<Record<string, unknown>>;
    const location = (
      results[0]?.['locations'] as Array<Record<string, Record<string, Record<string, unknown>>>>
    )[0];

    expect(location?.['physicalLocation']?.['artifactLocation']?.['uri']).toBe('src/api/client.ts');
    expect(output).not.toContain('/Users/example/work/app');
  });

  it('percent-encodes a path that is a legal filename but not a legal URI', () => {
    // `src/<img src=x onerror=alert(1)>.ts` is a filename a repository can
    // contain. Emitted raw it produces a SARIF file that fails validation, and a
    // rejected upload is silent from the developer's side.
    const document = parse(sarifReporter.render(hostileReport()));
    const run = (document['runs'] as Array<Record<string, unknown>>)[0] ?? {};
    const results = run['results'] as Array<Record<string, unknown>>;
    const location = (
      results[0]?.['locations'] as Array<Record<string, Record<string, Record<string, unknown>>>>
    )[0];
    const uri = location?.['physicalLocation']?.['artifactLocation']?.['uri'];

    expect(uri).toBe('src/%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E.ts');
    expect(uri).not.toContain('<');
  });

  it('includes the root only when asked', () => {
    const output = sarifReporter.render(sampleReport(), { includeRoot: true });

    expect(output).toContain('file:///Users/example/work/app/');
  });

  it('records an incomplete scan as a tool notification', () => {
    const document = parse(sarifReporter.render(sampleReport({ timedOut: true })));
    const run = (document['runs'] as Array<Record<string, unknown>>)[0] ?? {};
    const invocation = (run['invocations'] as Array<Record<string, unknown>>)[0] ?? {};
    const notifications = invocation['toolExecutionNotifications'] as Array<
      Record<string, Record<string, unknown>>
    >;

    expect(notifications[0]?.['message']?.['text']).toContain('INCOMPLETE SCAN');
  });

  it('marks the invocation unsuccessful when a rule threw', () => {
    const document = parse(
      sarifReporter.render(
        sampleReport({
          ruleErrors: [{ ruleId: 'RNSEC-RN-001', path: 'src/a.ts', message: 'boom' }],
        })
      )
    );
    const run = (document['runs'] as Array<Record<string, unknown>>)[0] ?? {};
    const invocation = (run['invocations'] as Array<Record<string, unknown>>)[0] ?? {};

    expect(invocation['executionSuccessful']).toBe(false);
  });
});
