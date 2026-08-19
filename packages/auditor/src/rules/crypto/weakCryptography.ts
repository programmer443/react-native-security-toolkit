import { buildFinding, evidence } from '../../analysis/findings.js';
import type { RawFinding } from '../../types/finding.js';
import type { KnowledgeRefs, RuleContext, SecurityRule } from '../../types/rule.js';

/**
 * RNSEC-CRYPTO-001 — a broken or misused cryptographic primitive.
 *
 * Three distinct problems, because they fail differently and are fixed
 * differently:
 *
 * - **Broken ciphers** — DES, 3DES, RC4. Not "old"; broken.
 * - **Broken hashes used as security primitives** — MD5 and SHA-1 have
 *   practical collision attacks. Both remain perfectly reasonable as
 *   non-security checksums, which is why the finding says *where* it saw them
 *   rather than banning the name outright.
 * - **ECB mode, and unauthenticated modes generally** — ECB leaks plaintext
 *   structure. `Cipher.getInstance("AES")` on Android is the sharpest edge here:
 *   it silently means `AES/ECB/PKCS5Padding`.
 *
 * The recommendation is always a platform primitive. §34 is explicit that a
 * security tool must never propose a bespoke algorithm.
 */

interface WeakPattern {
  readonly id: string;
  readonly pattern: RegExp;
  readonly title: string;
  readonly detail: string;
  readonly severity: RawFinding['severity'];
  readonly confidence: RawFinding['confidence'];
  readonly remediation: string;
  readonly knowledge: KnowledgeRefs;
  readonly languages?: readonly string[];
}

const HASH_KNOWLEDGE: KnowledgeRefs = {
  cwe: ['CWE-327', 'CWE-328'],
  masvs: ['MASVS-CRYPTO-1'],
  maswe: ['MASWE-0008'],
  mappingConfidence: 'high',
};

const CIPHER_KNOWLEDGE: KnowledgeRefs = {
  cwe: ['CWE-327', 'CWE-326'],
  masvs: ['MASVS-CRYPTO-1'],
  maswe: ['MASWE-0007'],
  mappingConfidence: 'high',
};

const MODERN_HASH =
  'Use SHA-256 or stronger. For passwords use a memory-hard KDF (Argon2id, scrypt or bcrypt), ' +
  'never a bare hash. If the value is a non-security checksum, say so in a comment so the next ' +
  'reader — and this rule — can tell the difference.';

const MODERN_CIPHER =
  'Use an authenticated mode from the platform library: AES-GCM (or ChaCha20-Poly1305) with a key ' +
  'from the Android Keystore or the iOS Keychain, and a unique nonce per message. Do not implement ' +
  'the construction by hand.';

const PATTERNS: readonly WeakPattern[] = [
  {
    id: 'md5',
    pattern:
      /\b(?:MessageDigest\.getInstance\(\s*["']MD5["']|CC_MD5|Insecure\.MD5|CryptoJS\.MD5|createHash\(\s*["']md5["']|["']md5["']\s*\)|MD5\.hash)/i,
    title: 'MD5 used as a security primitive',
    detail:
      'MD5 has practical collision attacks and must not be used where integrity or authenticity matters.',
    severity: 'high',
    confidence: 'high',
    remediation: MODERN_HASH,
    knowledge: HASH_KNOWLEDGE,
  },
  {
    id: 'sha1',
    pattern:
      /\b(?:MessageDigest\.getInstance\(\s*["']SHA-?1["']|CC_SHA1|Insecure\.SHA1|CryptoJS\.SHA1|createHash\(\s*["']sha1["'])/i,
    title: 'SHA-1 used as a security primitive',
    detail:
      'SHA-1 has practical collision attacks and is unsuitable for signatures, integrity checks or password handling.',
    severity: 'medium',
    confidence: 'high',
    remediation: MODERN_HASH,
    knowledge: HASH_KNOWLEDGE,
  },
  {
    id: 'des',
    pattern:
      /\b(?:Cipher\.getInstance\(\s*["'](?:DES|DESede|TripleDES)|kCCAlgorithmDES|kCCAlgorithm3DES|CryptoJS\.(?:DES|TripleDES)|["'](?:DES|DESede)\/)/,
    title: 'DES or Triple DES in use',
    detail:
      'DES has a 56-bit key and Triple DES a 64-bit block; both are withdrawn from use by NIST.',
    severity: 'high',
    confidence: 'high',
    remediation: MODERN_CIPHER,
    knowledge: CIPHER_KNOWLEDGE,
  },
  {
    id: 'rc4',
    pattern:
      /\b(?:Cipher\.getInstance\(\s*["']RC4|kCCAlgorithmRC4|CryptoJS\.RC4|["'](?:RC4|ARCFOUR)["'])/i,
    title: 'RC4 in use',
    detail: 'RC4 has known biases in its keystream and has been prohibited in TLS since RFC 7465.',
    severity: 'high',
    confidence: 'high',
    remediation: MODERN_CIPHER,
    knowledge: CIPHER_KNOWLEDGE,
  },
  {
    id: 'ecb-mode',
    pattern:
      /(?:Cipher\.getInstance\(\s*["'][A-Za-z0-9]+\/ECB|kCCOptionECBMode|CryptoJS\.mode\.ECB|["'][A-Za-z0-9]+-ecb["'])/i,
    title: 'ECB mode in use',
    detail:
      'ECB encrypts identical plaintext blocks to identical ciphertext blocks, so the structure of ' +
      'the plaintext survives encryption.',
    severity: 'high',
    confidence: 'high',
    remediation: MODERN_CIPHER,
    knowledge: CIPHER_KNOWLEDGE,
  },
  {
    id: 'implicit-ecb',
    // `Cipher.getInstance("AES")` is ECB on Android, silently.
    pattern: /Cipher\.getInstance\(\s*["'](?:AES|DES|DESede|Blowfish)["']\s*\)/,
    title: 'Cipher requested without a mode, which defaults to ECB',
    detail:
      'On Android, `Cipher.getInstance("AES")` resolves to AES/ECB/PKCS5Padding. The mode is not ' +
      'stated in the code, so the weakness is invisible at the call site.',
    severity: 'high',
    confidence: 'high',
    remediation: MODERN_CIPHER,
    knowledge: CIPHER_KNOWLEDGE,
    languages: ['kotlin', 'java'],
  },
  {
    id: 'unauthenticated-cbc',
    pattern: /Cipher\.getInstance\(\s*["'][A-Za-z0-9]+\/CBC\/[A-Za-z0-9]+["']\s*\)/,
    title: 'CBC mode without an authentication tag',
    detail:
      'CBC provides confidentiality but not integrity. Without a separate MAC, ciphertext can be ' +
      'modified in transit, and padding-oracle attacks become possible.',
    severity: 'medium',
    // The MAC may be applied elsewhere in the file or the codebase; this is an
    // indicator to check, not a proven defect.
    confidence: 'low',
    remediation: MODERN_CIPHER,
    knowledge: {
      cwe: ['CWE-327'],
      masvs: ['MASVS-CRYPTO-1'],
      maswe: ['MASWE-0007'],
      mappingConfidence: 'medium',
    },
  },
];

const IMPACT =
  'Data protected by a broken primitive is not protected. Depending on the primitive, an attacker ' +
  'may forge a value that passes an integrity check, recover plaintext structure, or brute-force ' +
  'the key with commodity hardware.';

const EXPLOITABILITY =
  'Requires access to the ciphertext or the hashed value — from device storage, a backup, or ' +
  'network capture. The attacks themselves are published and implemented in public tooling.';

export const weakCryptographyRule: SecurityRule = {
  id: 'RNSEC-CRYPTO-001',
  name: 'Broken or misused cryptographic primitive',
  description:
    'A cryptographic algorithm or mode with known practical attacks is used, or a cipher is ' +
    'requested in a way that silently selects one.',
  severity: 'high',
  categories: ['cryptography'],
  languages: [],
  fileKinds: [],
  // A code example in prose is not a defect.
  excludeFileKinds: ['documentation'],
  knowledge: {
    cwe: ['CWE-327', 'CWE-328', 'CWE-326'],
    masvs: ['MASVS-CRYPTO-1'],
    maswe: ['MASWE-0007', 'MASWE-0008'],
    mappingConfidence: 'high',
  },

  detect(context: RuleContext): readonly RawFinding[] {
    const findings: RawFinding[] = [];
    const reported = new Set<string>();

    context.lines.forEach((text, index) => {
      // A commented-out line is not a call. Cheap check, and it removes a
      // recurring class of false positive around migration notes.
      const code = stripComment(text, context.file.language);
      if (code.trim() === '') {
        return;
      }

      for (const weak of PATTERNS) {
        if (weak.languages !== undefined && !weak.languages.includes(context.file.language)) {
          continue;
        }
        if (!weak.pattern.test(code)) {
          continue;
        }

        const line = index + 1;
        const key = `${weak.id}:${line}`;
        if (reported.has(key)) {
          continue;
        }
        reported.add(key);

        findings.push(
          buildFinding({
            ruleId: 'RNSEC-CRYPTO-001',
            title: weak.title,
            description: weak.detail,
            severity: weak.severity,
            confidence: weak.confidence,
            categories: ['cryptography'],
            path: context.file.path,
            line,
            evidence: [
              evidence('matched-pattern', weak.title, { line, snippet: code.trim().slice(0, 200) }),
            ],
            impact: IMPACT,
            exploitability: EXPLOITABILITY,
            remediation: weak.remediation,
            structuralContext: weak.id,
            knowledge: weak.knowledge,
          })
        );
      }
    });

    return findings;
  },
};

/** Removes a trailing line comment so commented-out code is not reported as live. */
function stripComment(text: string, language: string): string {
  if (language === 'python' || language === 'yaml' || language === 'properties') {
    const hash = text.indexOf('#');
    return hash === -1 ? text : text.slice(0, hash);
  }
  const trimmed = text.trimStart();
  if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) {
    return '';
  }
  const comment = text.indexOf('//');
  return comment === -1 ? text : text.slice(0, comment);
}
