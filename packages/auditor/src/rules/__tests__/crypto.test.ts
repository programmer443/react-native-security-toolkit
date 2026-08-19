import { insecureRandomnessRule } from '../crypto/insecureRandomness.js';
import { weakCryptographyRule } from '../crypto/weakCryptography.js';
import { runRule } from './helpers/runRule.js';

describe('RNSEC-CRYPTO-001 broken or misused cryptographic primitive', () => {
  describe('true positives', () => {
    it('reports MD5 used through the platform API', async () => {
      const findings = await runRule(
        weakCryptographyRule,
        'android/app/src/main/java/com/app/Hashing.kt',
        'val digest = MessageDigest.getInstance("MD5").digest(input)'
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.title).toContain('MD5');
      expect(findings[0]?.severity).toBe('high');
    });

    it('reports an explicit ECB mode', async () => {
      const findings = await runRule(
        weakCryptographyRule,
        'android/app/src/main/java/com/app/Crypto.kt',
        'val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")'
      );

      expect(findings.some((finding) => finding.title.includes('ECB'))).toBe(true);
    });

    it('reports a cipher requested without a mode, which is ECB on Android', async () => {
      // The weakness is invisible at the call site, which is what makes it worth
      // a rule.
      const findings = await runRule(
        weakCryptographyRule,
        'android/app/src/main/java/com/app/Crypto.kt',
        'val cipher = Cipher.getInstance("AES")'
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.title).toContain('defaults to ECB');
    });

    it('reports DES and RC4 wherever they appear', async () => {
      const findings = await runRule(
        weakCryptographyRule,
        'src/legacy.ts',
        [
          'const a = CryptoJS.DES.encrypt(text, key);',
          'const b = CryptoJS.RC4.encrypt(text, key);',
        ].join('\n')
      );

      expect(findings).toHaveLength(2);
    });
  });

  describe('true negatives', () => {
    it('says nothing about modern authenticated cryptography', async () => {
      const findings = await runRule(
        weakCryptographyRule,
        'android/app/src/main/java/com/app/Crypto.kt',
        [
          'val cipher = Cipher.getInstance("AES/GCM/NoPadding")',
          'val digest = MessageDigest.getInstance("SHA-256").digest(input)',
        ].join('\n')
      );

      expect(findings).toEqual([]);
    });
  });

  describe('edge cases', () => {
    it('reports CBC without authentication at low confidence rather than not at all', async () => {
      // The MAC may exist elsewhere, so this is an indicator to check.
      const findings = await runRule(
        weakCryptographyRule,
        'android/app/src/main/java/com/app/Crypto.kt',
        'val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")'
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.confidence).toBe('low');
      expect(findings[0]?.severity).toBe('medium');
    });

    it('applies the implicit-ECB rule only to languages where it holds', async () => {
      // `crypto.createCipheriv('aes-256-gcm', ...)` in JavaScript has no such
      // default, so the Android-specific reasoning must not leak into it.
      const findings = await runRule(
        weakCryptographyRule,
        'src/crypto.ts',
        'const cipher = createCipheriv("aes-256-gcm", key, iv);'
      );

      expect(findings).toEqual([]);
    });
  });

  describe('false positives it must not produce', () => {
    it('ignores a commented-out line', async () => {
      const findings = await runRule(
        weakCryptographyRule,
        'src/legacy.ts',
        '// we used to call CryptoJS.MD5(value) here; replaced with SHA-256'
      );

      expect(findings).toEqual([]);
    });

    it('does not report the same weakness twice on one line', async () => {
      const findings = await runRule(
        weakCryptographyRule,
        'src/legacy.ts',
        'const digest = CryptoJS.MD5(CryptoJS.MD5(value));'
      );

      expect(findings).toHaveLength(1);
    });
  });
});

describe('RNSEC-CRYPTO-002 predictable randomness', () => {
  describe('true positives', () => {
    it('reports Math.random used to build a token', async () => {
      const findings = await runRule(
        insecureRandomnessRule,
        'src/auth/token.ts',
        'const sessionToken = Math.random().toString(36).slice(2);'
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.severity).toBe('high');
    });

    it('reports java.util.Random used for a key', async () => {
      const findings = await runRule(
        insecureRandomnessRule,
        'android/app/src/main/java/com/app/Keys.kt',
        'val encryptionKey = ByteArray(16).also { Random().nextBytes(it) }'
      );

      expect(findings).toHaveLength(1);
    });
  });

  describe('true negatives', () => {
    it('says nothing about randomness used for presentation', async () => {
      // Flagging every Math.random is how a rule gets switched off, taking the
      // real findings with it.
      const findings = await runRule(
        insecureRandomnessRule,
        'src/ui/animation.ts',
        [
          'const jitter = Math.random() * 100;',
          'const shuffleSeed = Math.random();',
          'const placeholderIndex = Math.floor(Math.random() * items.length);',
        ].join('\n')
      );

      expect(findings).toEqual([]);
    });

    it('says nothing about crypto.getRandomValues', async () => {
      const findings = await runRule(
        insecureRandomnessRule,
        'src/auth/token.ts',
        'const sessionToken = crypto.getRandomValues(new Uint8Array(32));'
      );

      expect(findings).toEqual([]);
    });
  });

  describe('edge cases', () => {
    it('reports Date.now used as a source of unpredictability', async () => {
      const findings = await runRule(
        insecureRandomnessRule,
        'src/auth/token.ts',
        'const nonce = String(Date.now());'
      );

      expect(findings).toHaveLength(1);
    });

    it('takes the enclosing function name as the context when there is no variable', async () => {
      const findings = await runRule(
        insecureRandomnessRule,
        'src/auth/token.ts',
        'function generateOtp() {\n  return Math.random().toString().slice(2, 8);\n}'
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.title).toContain('generateOtp');
    });
  });

  describe('false positives it must not produce', () => {
    it('ignores a random value explicitly named as a mock or sample', async () => {
      const findings = await runRule(
        insecureRandomnessRule,
        'src/dev/mocks.ts',
        'const mockSessionId = Math.random().toString(36);'
      );

      expect(findings).toEqual([]);
    });
  });
});
