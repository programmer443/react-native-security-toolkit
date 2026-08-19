/**
 * Configuration for the toolkit's audit of its own repository (§58).
 *
 * Run it with `pnpm security:audit`.
 *
 * This file is also the worked example of the configuration format: it is
 * parsed and statically evaluated, never imported, exactly as a consuming
 * project's would be.
 *
 * Two exclusions, both for the same reason — a security scanner contains, by
 * construction, the things it looks for:
 *
 * - `packages/auditor/src/rules/**` holds the signature definitions. The rule
 *   that detects `rejectUnauthorized: false` contains that string, and the rule
 *   that detects MD5 names MD5. Scanning them reports the detector as the defect.
 * - `fixtures/**` is deliberately vulnerable code that exists to make rules fire.
 *   It is scanned on purpose by `src/__tests__/fixtureProjects.test.ts`, which is
 *   where those findings belong.
 *
 * Everything else — including the toolkit's own tests — is scanned. Sample
 * credentials in test files are suppressed inline, with a reason, which is how a
 * consuming project is expected to handle them too.
 */
export default {
  profile: 'standard',

  exclude: ['packages/auditor/src/rules/**', 'fixtures/**'],

  severity: {
    failOn: 'high',
  },

  /**
   * The baseline: findings accepted by fingerprint, each with a reason.
   *
   * Every entry here is a *true* positive — the text really is in the file. They
   * are attack strings this toolkit's own tests and documentation need in order
   * to prove the detection works, which is the one situation where "this is
   * fine" is the correct answer. Fingerprints exclude line numbers, so these
   * survive edits elsewhere in the file.
   */
  ignore: [
    {
      fingerprint: '5e41fc6aad88c9a894abefd088dfe9ac',
      reason: "AWS's published example key, used as scanner input in the MCP server's tests",
    },
    {
      fingerprint: '3eb55dba74f6fe773bcb37c43277b3f0',
      reason: 'injection example quoted in the MCP untrusted-content module documentation',
    },
    {
      fingerprint: '29624f3570e4ebbbfd6a535c160b7d47',
      reason: 'injection example quoted in the MCP untrusted-content module documentation',
    },
    {
      fingerprint: 'aba3431afc2186d2cb82004f107eee1d',
      reason: 'prompt-injection fixture in the hostile-repository test suite',
    },
    {
      fingerprint: 'df4ca343173560c9a6f4fb9e99a9704e',
      reason: 'prompt-injection fixture in the hostile-repository test suite',
    },
    {
      fingerprint: '35a5e3b7e0887b168784f1a76e44ca0a',
      reason: 'prompt-injection fixture in the hostile-repository test suite',
    },
    {
      fingerprint: '5b4872e629ab00f9ec3c0d003be6b66d',
      reason: 'injection fixture proving the MCP server surfaces it rather than acting on it',
    },
    {
      fingerprint: '5d20c4518ad686940429c819e44b8e6a',
      reason: 'injection-detection test case for the role-reassignment pattern',
    },
    {
      fingerprint: 'abacf0f723d8a809d26f52648142d224',
      reason: 'injection-detection test case for the prompt-extraction pattern',
    },
    {
      fingerprint: '8805e10abcd471b8387f614c9b6d3482',
      reason: 'injection-detection test case for the exfiltration pattern',
    },
    {
      fingerprint: 'e66cdbca542bd1b0528c348ca78faa50',
      reason: 'injection-detection test case for the chat-template-token pattern',
    },
  ],

  ai: {
    enabled: false,
  },
};
