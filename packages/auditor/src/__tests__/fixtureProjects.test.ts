import fs from 'node:fs';
import path from 'node:path';

import { auditProject } from '../engine/auditProject.js';
import { builtinRules } from '../rules/index.js';
import { defaultConfig } from '../config/defaults.js';
import type { AuditReport } from '../types/report.js';

/**
 * The rule library, run against two whole projects.
 *
 * The vulnerable fixture proves the rules fire on real files rather than on the
 * one-line snippets in their unit tests. The secure fixture is the harder and
 * more important half: it is the same application written safely, and **every
 * finding it produces is a false positive**. A scanner is judged on that number.
 */

const fixtures = path.resolve(process.cwd(), '../../fixtures');
const vulnerable = path.join(fixtures, 'vulnerable-react-native');
const secure = path.join(fixtures, 'secure-react-native');

const describeIfPresent = fs.existsSync(vulnerable) ? describe : describe.skip;

async function scan(root: string): Promise<AuditReport> {
  return auditProject({
    root,
    rules: [...builtinRules],
    // `info` so nothing is hidden by the reporting floor — a fixture path is
    // downgraded two levels by the severity engine, and this test is about
    // detection rather than presentation.
    config: { ...defaultConfig(), minimumSeverity: 'info' },
  });
}

describeIfPresent('the rule library against fixture projects', () => {
  describe('vulnerable-react-native', () => {
    it('reports every rule the fixture was written to trip', async () => {
      const report = await scan(vulnerable);
      const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));

      expect([...ruleIds].sort()).toEqual(
        [
          'RNSEC-AI-001',
          'RNSEC-ANDROID-MANIFEST-001',
          'RNSEC-ANDROID-MANIFEST-002',
          'RNSEC-CRYPTO-001',
          'RNSEC-CRYPTO-002',
          'RNSEC-DEPS-001',
          'RNSEC-DEEPLINK-001',
          'RNSEC-IOS-PLIST-001',
          'RNSEC-LOG-001',
          'RNSEC-NETWORK-001',
          'RNSEC-RN-001',
          'RNSEC-SECRET-001',
          'RNSEC-STORAGE-001',
          'RNSEC-WEBVIEW-001',
        ].sort()
      );
    });

    it('attaches real standards references to what it reports', async () => {
      const report = await scan(vulnerable);
      const secret = report.findings.find((finding) => finding.ruleId === 'RNSEC-SECRET-001');

      expect(secret?.cwe?.[0]).toMatchObject({
        id: 'CWE-798',
        title: 'Use of Hard-coded Credentials',
      });
      expect(secret?.maswe?.[0]?.id).toBe('MASWE-0004');
      expect(secret?.masvs?.[0]?.id).toBe('MASVS-STORAGE-1');
    });

    it('runs every rule without any of them throwing', async () => {
      const report = await scan(vulnerable);

      expect(report.ruleErrors).toEqual([]);
      expect(report.timedOut).toBe(false);
    });
  });

  describe('secure-react-native', () => {
    it('reports nothing at all', async () => {
      // Every finding here would be a false positive. The list is printed on
      // failure so the offender is obvious.
      const report = await scan(secure);

      expect(
        report.findings.map(
          (finding) =>
            `${finding.ruleId} ${finding.location.path}:${finding.location.line ?? 0} ${finding.title}`
        )
      ).toEqual([]);
    });

    it('still reads every file, rather than reporting nothing because it scanned nothing', async () => {
      const report = await scan(secure);

      expect(report.stats.filesAnalysed).toBeGreaterThanOrEqual(7);
      expect(report.stats.filesParsed).toBeGreaterThanOrEqual(3);
    });
  });
});
