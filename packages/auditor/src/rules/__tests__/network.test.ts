import { cleartextTrafficRule } from '../network/cleartextTraffic.js';
import { disabledTlsValidationRule } from '../network/disabledTlsValidation.js';
import { runRule } from './helpers/runRule.js';

describe('RNSEC-NETWORK-001 cleartext HTTP endpoint', () => {
  describe('true positives', () => {
    it('reports an HTTP API base URL', async () => {
      const findings = await runRule(
        cleartextTrafficRule,
        'src/api/client.ts',
        'const baseUrl = "http://api.example-bank.com/v1";'
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.title).toContain('api.example-bank.com');
      expect(findings[0]?.severity).toBe('high');
    });

    it('reports a cleartext URL in a native source file', async () => {
      const findings = await runRule(
        cleartextTrafficRule,
        'android/app/src/main/java/com/app/Api.kt',
        'private const val ENDPOINT = "http://payments.internal-corp.net/charge"'
      );

      expect(findings).toHaveLength(1);
    });
  });

  describe('true negatives', () => {
    it('says nothing about HTTPS', async () => {
      const findings = await runRule(
        cleartextTrafficRule,
        'src/api/client.ts',
        'const baseUrl = "https://api.example-bank.com/v1";'
      );

      expect(findings).toEqual([]);
    });

    it('says nothing about local development addresses', async () => {
      const findings = await runRule(
        cleartextTrafficRule,
        'src/api/client.ts',
        [
          'const dev = "http://localhost:8081/index.bundle";',
          'const emulator = "http://10.0.2.2:3000";',
          'const lan = "http://192.168.1.14:8081";',
        ].join('\n')
      );

      expect(findings).toEqual([]);
    });
  });

  describe('edge cases', () => {
    it('reports one finding per host rather than one per call site', async () => {
      // A base URL repeated across ten calls is one decision to fix.
      const findings = await runRule(
        cleartextTrafficRule,
        'src/api/client.ts',
        [
          'fetch("http://api.insecure-service.com/a");',
          'fetch("http://api.insecure-service.com/b");',
          'fetch("http://api.insecure-service.com/c");',
        ].join('\n')
      );

      expect(findings).toHaveLength(1);
    });
  });

  describe('false positives it must not produce', () => {
    it('ignores XML namespaces and DTD identifiers', async () => {
      // `http://schemas.android.com/apk/res/android` is in every manifest ever
      // written, and is not an endpoint.
      const findings = await runRule(
        cleartextTrafficRule,
        'android/app/src/main/AndroidManifest.xml',
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.app">'
      );

      expect(findings).toEqual([]);
    });

    it('ignores RFC 2606 documentation domains', async () => {
      const findings = await runRule(
        cleartextTrafficRule,
        'src/api/client.ts',
        'const sample = "http://example.com/docs";'
      );

      expect(findings).toEqual([]);
    });

    it('does not scan documentation files at all', async () => {
      expect(cleartextTrafficRule.fileKinds).not.toContain('documentation');
    });
  });
});

describe('RNSEC-NETWORK-002 TLS validation disabled', () => {
  describe('true positives', () => {
    it('reports rejectUnauthorized: false', async () => {
      const findings = await runRule(
        disabledTlsValidationRule,
        'src/api/agent.ts',
        'const agent = new https.Agent({ rejectUnauthorized: false });'
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.severity).toBe('critical');
      expect(findings[0]?.confidence).toBe('very-high');
    });

    it('reports a permissive hostname verifier on Android', async () => {
      const findings = await runRule(
        disabledTlsValidationRule,
        'android/app/src/main/java/com/app/Http.kt',
        'builder.setHostnameVerifier { _, _ -> true }'
      );

      expect(findings).toHaveLength(1);
    });

    it('reports accepting the server trust on iOS', async () => {
      const findings = await runRule(
        disabledTlsValidationRule,
        'ios/Api.swift',
        'completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))'
      );

      expect(findings).toHaveLength(1);
    });
  });

  describe('true negatives', () => {
    it('says nothing about ordinary client configuration', async () => {
      const findings = await runRule(
        disabledTlsValidationRule,
        'src/api/agent.ts',
        'const client = axios.create({ baseURL: "https://api.example.com", timeout: 5000 });'
      );

      expect(findings).toEqual([]);
    });
  });

  describe('edge cases', () => {
    it('reports a custom trust manager as an indicator, not a verdict', async () => {
      // Certificate pinning is implemented this way too, so the finding says
      // "review this" rather than "this is broken".
      const findings = await runRule(
        disabledTlsValidationRule,
        'android/app/src/main/java/com/app/Http.kt',
        'private val trustManager = object : X509TrustManager {'
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.confidence).toBe('medium');
      expect(findings[0]?.severity).toBe('high');
    });

    it('reports each distinct weakness once per file', async () => {
      const findings = await runRule(
        disabledTlsValidationRule,
        'src/api/agent.ts',
        [
          'const a = { rejectUnauthorized: false };',
          'const b = { rejectUnauthorized: false };',
        ].join('\n')
      );

      expect(findings).toHaveLength(1);
    });
  });

  describe('false positives it must not produce', () => {
    it('ignores a commented-out override', async () => {
      const findings = await runRule(
        disabledTlsValidationRule,
        'src/api/agent.ts',
        '// during migration we set rejectUnauthorized: false here'
      );

      expect(findings).toEqual([]);
    });

    it('ignores a hostname verifier written in a language the pattern does not claim', async () => {
      const findings = await runRule(
        disabledTlsValidationRule,
        'src/api/agent.ts',
        'const verifier = new HostnameVerifier();'
      );

      expect(findings).toEqual([]);
    });
  });
});
