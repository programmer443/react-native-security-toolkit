import { SecurityToolkitError } from '../internal/errors';
import { parseEngineInfo } from '../internal/validate';

const valid = {
  platform: 'android',
  osVersion: '15',
  engineVersion: '0.1.0',
  supportedChecks: ['root'],
};

describe('native payload validation', () => {
  it('accepts and freezes a well-formed payload', () => {
    const info = parseEngineInfo(valid);
    expect(info).toEqual(valid);
    expect(Object.isFrozen(info)).toBe(true);
    expect(Object.isFrozen(info.supportedChecks)).toBe(true);
  });

  it('accepts an empty supportedChecks list', () => {
    expect(parseEngineInfo({ ...valid, supportedChecks: [] }).supportedChecks).toEqual([]);
  });

  // A hooked or tampered native module is exactly the environment this package
  // is meant to run in, so a malformed payload must be rejected rather than
  // handed to application code.
  describe('rejects payloads a tampered native module could return', () => {
    const cases: ReadonlyArray<[string, unknown]> = [
      ['a null payload', null],
      ['a string payload', 'compromised'],
      ['an array payload', []],
      ['a missing platform', { ...valid, platform: undefined }],
      ['an empty platform', { ...valid, platform: '' }],
      ['an unknown platform', { ...valid, platform: 'windows' }],
      ['a numeric osVersion', { ...valid, osVersion: 15 }],
      ['a missing engineVersion', { ...valid, engineVersion: undefined }],
      ['a non-array supportedChecks', { ...valid, supportedChecks: 'root' }],
      ['a non-string entry in supportedChecks', { ...valid, supportedChecks: ['root', 7] }],
    ];

    it.each(cases)('%s', (_label, payload) => {
      expect(() => parseEngineInfo(payload)).toThrow(SecurityToolkitError);
      try {
        parseEngineInfo(payload);
      } catch (error) {
        expect((error as SecurityToolkitError).code).toBe('INVALID_NATIVE_PAYLOAD');
      }
    });
  });

  it('names the offending field without dumping the payload', () => {
    expect(() => parseEngineInfo({ ...valid, osVersion: 15 })).toThrow(
      /expected "osVersion" to be a non-empty string, received number/
    );
  });

  it('reports the offending index for a bad array entry', () => {
    expect(() => parseEngineInfo({ ...valid, supportedChecks: ['root', 7] })).toThrow(
      /"supportedChecks\[1\]"/
    );
  });
});
