import {
  DEFAULT_OPTIONS,
  getConfiguration,
  resetConfiguration,
  resolveOptions,
  setConfiguration,
} from '../internal/config';
import { SecurityToolkitError } from '../internal/errors';

describe('configuration', () => {
  afterEach(() => {
    resetConfiguration();
  });

  it('applies documented defaults when nothing is supplied', () => {
    expect(resolveOptions({})).toEqual(DEFAULT_OPTIONS);
    expect(DEFAULT_OPTIONS.developmentMode).toBe(false);
    expect(DEFAULT_OPTIONS.nativeTimeoutMs).toBe(5_000);
    expect(DEFAULT_OPTIONS.disabledChecks).toEqual([]);
    expect(DEFAULT_OPTIONS.integrity).toEqual({});
  });

  it('keeps the resolved configuration immutable', () => {
    const resolved = resolveOptions({ disabledChecks: ['root'] });
    expect(Object.isFrozen(resolved)).toBe(true);
    expect(Object.isFrozen(resolved.disabledChecks)).toBe(true);
  });

  it('copies disabledChecks so later caller mutation cannot change behaviour', () => {
    const caller = ['root'] as const;
    const mutable: string[] = [...caller];
    const resolved = resolveOptions({ disabledChecks: mutable as never });
    mutable.push('debugger');
    expect(resolved.disabledChecks).toEqual(['root']);
  });

  it('round-trips through the module-level store', () => {
    setConfiguration({ developmentMode: true, nativeTimeoutMs: 250 });
    expect(getConfiguration().developmentMode).toBe(true);
    expect(getConfiguration().nativeTimeoutMs).toBe(250);
    resetConfiguration();
    expect(getConfiguration()).toEqual(DEFAULT_OPTIONS);
  });

  describe('rejects invalid input rather than silently defaulting', () => {
    const cases: ReadonlyArray<[string, unknown]> = [
      ['a non-object', 'nope'],
      ['null', null],
      ['a non-boolean developmentMode', { developmentMode: 'yes' }],
      ['a non-numeric timeout', { nativeTimeoutMs: '500' }],
      ['a non-finite timeout', { nativeTimeoutMs: Number.POSITIVE_INFINITY }],
      ['a timeout below the floor', { nativeTimeoutMs: 10 }],
      ['a timeout above the ceiling', { nativeTimeoutMs: 120_000 }],
      ['a non-array disabledChecks', { disabledChecks: 'root' }],
      ['an unknown check id', { disabledChecks: ['rooot'] }],
    ];

    it.each(cases)('%s', (_label, value) => {
      expect(() => resolveOptions(value as never)).toThrow(SecurityToolkitError);
      try {
        resolveOptions(value as never);
      } catch (error) {
        expect((error as SecurityToolkitError).code).toBe('INVALID_CONFIGURATION');
      }
    });
  });

  it('names the valid checks when rejecting an unknown one', () => {
    expect(() => resolveOptions({ disabledChecks: ['rooot'] as never })).toThrow(
      /Valid checks: root, jailbreak, debugger, emulator, simulator/
    );
  });

  it('accepts the boundary timeout values', () => {
    expect(resolveOptions({ nativeTimeoutMs: 100 }).nativeTimeoutMs).toBe(100);
    expect(resolveOptions({ nativeTimeoutMs: 60_000 }).nativeTimeoutMs).toBe(60_000);
  });

  describe('integrity configuration', () => {
    const validFingerprint = 'A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90';

    it('accepts a well-formed configuration', () => {
      const resolved = resolveOptions({
        integrity: {
          signingCertificateSha256: [validFingerprint],
          expectedInstallers: ['com.android.vending'],
          expectedPackageName: 'com.example.app',
        },
      });

      expect(resolved.integrity.signingCertificateSha256).toEqual([validFingerprint]);
      expect(Object.isFrozen(resolved.integrity)).toBe(true);
    });

    it('accepts a fingerprint however the caller punctuated it', () => {
      const punctuated = validFingerprint.match(/.{2}/g)?.join(':').toLowerCase() ?? '';

      expect(() =>
        resolveOptions({ integrity: { signingCertificateSha256: [punctuated] } })
      ).not.toThrow();
    });

    it('omits absent sub-options rather than setting them undefined', () => {
      const resolved = resolveOptions({ integrity: { expectedPackageName: 'com.example.app' } });

      expect('signingCertificateSha256' in resolved.integrity).toBe(false);
      expect('expectedInstallers' in resolved.integrity).toBe(false);
    });

    /**
     * A mistyped fingerprint would make every launch look like a tampered
     * build, and an empty array would silently disable the strongest integrity
     * signal there is. Both are worth being loud about.
     */
    describe('rejects configuration mistakes rather than absorbing them', () => {
      const cases: ReadonlyArray<[string, unknown]> = [
        ['a non-object integrity block', { integrity: 'yes' }],
        ['an empty fingerprint array', { integrity: { signingCertificateSha256: [] } }],
        [
          'a non-array fingerprint value',
          { integrity: { signingCertificateSha256: validFingerprint } },
        ],
        ['a truncated fingerprint', { integrity: { signingCertificateSha256: ['A1B2C3'] } }],
        ['a non-hex fingerprint', { integrity: { signingCertificateSha256: ['Z'.repeat(64)] } }],
        ['a non-string fingerprint', { integrity: { signingCertificateSha256: [123] } }],
        ['an empty installer array', { integrity: { expectedInstallers: [] } }],
        ['an empty installer name', { integrity: { expectedInstallers: [''] } }],
        ['an empty package name', { integrity: { expectedPackageName: '' } }],
        ['an empty bundle identifier', { integrity: { expectedBundleIdentifier: '' } }],
      ];

      it.each(cases)('%s', (_label, value) => {
        expect(() => resolveOptions(value as never)).toThrow(SecurityToolkitError);
      });
    });

    it('names the offending fingerprint so the mistake is findable', () => {
      expect(() => resolveOptions({ integrity: { signingCertificateSha256: ['A1B2C3'] } })).toThrow(
        /not a SHA-256 fingerprint: "A1B2C3"/
      );
    });
  });
});
