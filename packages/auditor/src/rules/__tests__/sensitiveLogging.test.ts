import { sensitiveLoggingRule } from '../logging/sensitiveLogging.js';
import { runRule } from './helpers/runRule.js';

describe('RNSEC-LOG-001 sensitive data written to a log', () => {
  describe('true positives', () => {
    it('reports a token passed to console.log', async () => {
      const findings = await runRule(
        sensitiveLoggingRule,
        'src/auth/session.ts',
        'console.log(accessToken);'
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.confidence).toBe('high');
    });

    it('reports a sensitive value interpolated into a message', async () => {
      const findings = await runRule(
        sensitiveLoggingRule,
        'src/auth/session.ts',
        'console.warn(`auth header: ${authorization}`);'
      );

      expect(findings).toHaveLength(1);
    });

    it('reports a shorthand object property', async () => {
      const findings = await runRule(
        sensitiveLoggingRule,
        'src/auth/session.ts',
        'console.debug("login", { refreshToken });'
      );

      expect(findings).toHaveLength(1);
    });

    it('sees through JSON.stringify', async () => {
      const findings = await runRule(
        sensitiveLoggingRule,
        'src/auth/session.ts',
        'console.log(JSON.stringify(credentials));'
      );

      expect(findings).toHaveLength(1);
      // Serialising hides nothing, but the indirection lowers confidence a step.
      expect(findings[0]?.confidence).toBe('medium');
    });

    it('reports Android and iOS log sinks', async () => {
      const android = await runRule(
        sensitiveLoggingRule,
        'android/app/src/main/java/com/app/Auth.kt',
        'Log.d(TAG, "token=" + accessToken)'
      );
      const ios = await runRule(
        sensitiveLoggingRule,
        'ios/Auth.swift',
        'NSLog("session %@", sessionToken)'
      );

      expect(android).toHaveLength(1);
      expect(ios).toHaveLength(1);
    });
  });

  describe('true negatives', () => {
    it('says nothing about ordinary logging', async () => {
      // §34: do not flag every logging statement.
      const findings = await runRule(
        sensitiveLoggingRule,
        'src/app.ts',
        [
          'console.log("App mounted");',
          'console.error("Failed to load profile", error);',
          'console.info(`Rendering ${items.length} items`);',
        ].join('\n')
      );

      expect(findings).toEqual([]);
    });

    it('says nothing when a sensitive word appears only in a message string', async () => {
      const findings = await runRule(
        sensitiveLoggingRule,
        'src/app.ts',
        'console.log("password reset requested");'
      );

      expect(findings).toEqual([]);
    });
  });

  describe('edge cases', () => {
    it('reports once per statement even with several sensitive arguments', async () => {
      const findings = await runRule(
        sensitiveLoggingRule,
        'src/auth/session.ts',
        'console.log(accessToken, refreshToken);'
      );

      expect(findings).toHaveLength(1);
    });

    it('reads the property name of a member expression', async () => {
      const findings = await runRule(
        sensitiveLoggingRule,
        'src/auth/session.ts',
        'console.log(response.accessToken);'
      );

      expect(findings).toHaveLength(1);
    });
  });

  describe('false positives it must not produce', () => {
    it('ignores token counts and tokenizers', async () => {
      const findings = await runRule(
        sensitiveLoggingRule,
        'src/llm/usage.ts',
        ['console.log(tokenCount);', 'console.log(tokenizer.name);'].join('\n')
      );

      expect(findings).toEqual([]);
    });

    it('ignores a native log line that mentions nothing sensitive', async () => {
      const findings = await runRule(
        sensitiveLoggingRule,
        'android/app/src/main/java/com/app/Auth.kt',
        'Log.d(TAG, "sync finished in " + elapsedMs + "ms")'
      );

      expect(findings).toEqual([]);
    });

    it('ignores a public key, which is public', async () => {
      const findings = await runRule(
        sensitiveLoggingRule,
        'src/crypto.ts',
        'console.log(publicKey);'
      );

      expect(findings).toEqual([]);
    });
  });
});
