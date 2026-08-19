import { hardcodedSecretRule } from '../secrets/hardcodedSecret.js';
import { runRule } from './helpers/runRule.js';

/**
 * Every rule is tested against four cases (§55): a true positive, a true
 * negative, an edge case, and the false positive it would most plausibly
 * produce. The last of those is the one that decides whether anyone keeps the
 * rule switched on.
 */
describe('RNSEC-SECRET-001 hardcoded credential', () => {
  describe('true positives', () => {
    it('reports a credential whose format identifies its issuer', async () => {
      const findings = await runRule(
        hardcodedSecretRule,
        'src/api/client.ts',
        'const client = createClient({ region: "eu-west-1", accessKeyId: "AKIAIOSFODNN7EXAMPLE" });'
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.title).toContain('AWS access key id');
      expect(findings[0]?.confidence).toBe('very-high');
      expect(findings[0]?.severity).toBe('critical');
    });

    it('reports a sensitive name assigned a secret-shaped literal', async () => {
      const findings = await runRule(
        hardcodedSecretRule,
        'src/api/client.ts',
        'const apiSecret = "Kq7#pR2vX9!mZ4tW8bN6yL3sD5fG1hJ0";'
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.confidence).toBe('medium');
      expect(findings[0]?.title).toContain('apiSecret');
    });

    it('reports a private key block in any language', async () => {
      const findings = await runRule(
        hardcodedSecretRule,
        'android/app/src/main/java/com/app/Keys.kt',
        'const val KEY = """-----BEGIN RSA PRIVATE KEY-----"""'
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.title).toContain('PEM private key');
    });

    it('masks the value instead of reproducing it in the report', async () => {
      // A findings file travels into pull requests and CI logs — much further
      // than the source file it came from.
      const findings = await runRule(
        hardcodedSecretRule,
        'src/api/client.ts',
        'const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";'
      );

      const snippet = findings[0]?.evidence[0]?.snippet ?? '';
      expect(snippet).not.toContain('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
      expect(snippet).toContain('*');
    });
  });

  describe('true negatives', () => {
    it('says nothing about a credential read from the environment', async () => {
      // This is the correct pattern, and reporting it would teach people to
      // ignore the rule.
      const findings = await runRule(
        hardcodedSecretRule,
        'src/api/client.ts',
        'const apiKey = process.env.API_KEY;\nconst token = await keychain.get("session");'
      );

      expect(findings).toEqual([]);
    });

    it('says nothing about a sensitive name assigned an ordinary value', async () => {
      const findings = await runRule(
        hardcodedSecretRule,
        'src/api/client.ts',
        'const passwordLabel = "Enter your password";\nconst tokenType = "Bearer";'
      );

      expect(findings).toEqual([]);
    });
  });

  describe('edge cases', () => {
    it('reads a credential out of a template literal with no substitutions', async () => {
      const findings = await runRule(
        hardcodedSecretRule,
        'src/api/client.ts',
        'const clientSecret = `Kq7#pR2vX9!mZ4tW8bN6yL3sD5fG1hJ0`;'
      );

      expect(findings).toHaveLength(1);
    });

    it('does not report the same line twice when both passes match it', async () => {
      // The named pattern is the better finding; the entropy heuristic must not
      // pile a second, weaker finding onto the same line.
      const findings = await runRule(
        hardcodedSecretRule,
        'src/api/client.ts',
        'const apiKey = "AIzaSyDHtSGhTfKzKt7c0OvvIu5jGgFHhJkLmNo";'
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.confidence).toBe('very-high');
    });

    it('handles a file with no parse result by falling back to the pattern pass', async () => {
      const findings = await runRule(
        hardcodedSecretRule,
        'android/app/build.gradle',
        // Assembled rather than written out: a contiguous live-key-shaped string in
        // a public repository trips secret scanners, and this one is not a credential.
        `buildConfigField "String", "KEY", "\\"sk_${'live'}_4eC39HqLyjWDarjtT1zdp7dc\\""`
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.title).toContain('Stripe');
    });
  });

  describe('false positives it must not produce', () => {
    it('ignores UUIDs, git hashes and version strings', async () => {
      const findings = await runRule(
        hardcodedSecretRule,
        'src/config.ts',
        [
          'const sessionId = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";',
          'const buildKey = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";',
          'const tokenVersion = "1.2.3";',
        ].join('\n')
      );

      expect(findings).toEqual([]);
    });

    it('ignores obvious placeholders', async () => {
      const findings = await runRule(
        hardcodedSecretRule,
        'src/config.ts',
        [
          'const apiKey = "YOUR_API_KEY_HERE";',
          'const password = "changeme";',
          'const secret = "xxxxxxxxxxxxxxxx";',
        ].join('\n')
      );

      expect(findings).toEqual([]);
    });

    it('ignores a base64 asset assigned to a name that is not sensitive', async () => {
      const findings = await runRule(
        hardcodedSecretRule,
        'src/assets.ts',
        'export const logo = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";'
      );

      expect(findings).toEqual([]);
    });

    it('ignores a tokenizer, which is not a token', async () => {
      const findings = await runRule(
        hardcodedSecretRule,
        'src/text.ts',
        'const tokenizerConfig = "aGVsbG8gd29ybGQgdGhpcyBpcyBub3QgYSBzZWNyZXQ=";'
      );

      expect(findings).toEqual([]);
    });
  });
});
