import { AuditorConfigError, resolveConfig } from '../resolveConfig.js';
import { DEFAULT_EXCLUDE } from '../defaults.js';

describe('configuration resolution', () => {
  it('returns usable defaults when a project supplies nothing', () => {
    const config = resolveConfig(undefined);

    expect(config.profile).toBe('standard');
    expect(config.failOn).toBe('high');
    expect(config.minimumSeverity).toBe('low');
    expect(config.exclude).toEqual([...DEFAULT_EXCLUDE]);
    expect(config.ai.enabled).toBe(false);
  });

  it('sets the reporting floor from the profile', () => {
    expect(resolveConfig({ profile: 'minimal' }).minimumSeverity).toBe('high');
    expect(resolveConfig({ profile: 'strict' }).minimumSeverity).toBe('info');
  });

  it('lets an explicit minimum override the profile', () => {
    expect(
      resolveConfig({ profile: 'minimal', severity: { minimum: 'info' } }).minimumSeverity
    ).toBe('info');
  });

  it('extends the default exclusions rather than replacing them', () => {
    // Replacing them is a footgun: adding one exclusion would silently start
    // scanning node_modules, and the first sign would be a scan that never ends.
    const config = resolveConfig({ exclude: ['docs/**'] });

    expect(config.exclude).toContain('**/node_modules/**');
    expect(config.exclude).toContain('docs/**');
  });

  it('rejects an unknown option instead of ignoring it', () => {
    // A misspelled key that silently does nothing is how a project comes to
    // believe a rule is disabled when it is not.
    expect(() => resolveConfig({ excludes: ['docs/**'] })).toThrow(AuditorConfigError);
    expect(() => resolveConfig({ excludes: ['docs/**'] })).toThrow(/not a known option/);
  });

  it.each([
    [{ profile: 'paranoid' }, /profile/],
    [{ include: 'src/**' }, /include/],
    [{ include: [''] }, /include/],
    [{ severity: { failOn: 'catastrophic' } }, /severity.failOn/],
    [{ limits: { maxFiles: 0 } }, /limits.maxFiles/],
    [{ limits: { maxWidgets: 4 } }, /not a known limit/],
    [{ rules: { overrides: { 'RNSEC-LOG-001': 'low' } } }, /must be an array/],
  ])('rejects %p', (options, message) => {
    expect(() => resolveConfig(options)).toThrow(message);
  });

  it('requires a reason on every baseline entry', () => {
    // An unexplained suppression is a finding somebody hid, and there is no way
    // to tell later whether it was reviewed (§43).
    expect(() => resolveConfig({ ignore: [{ fingerprint: 'a1b2c3d4e5f6a7b8' }] as never })).toThrow(
      /reason.*required/
    );
  });

  it('rejects a baseline fingerprint that is not one', () => {
    expect(() => resolveConfig({ ignore: [{ fingerprint: 'nope', reason: 'x' }] })).toThrow(
      /fingerprint/
    );
  });

  it('accepts a well-formed override', () => {
    const config = resolveConfig({
      rules: {
        disabled: ['RNSEC-SECRET-001'],
        overrides: [{ rule: 'RNSEC-LOG-001', severity: 'low', paths: ['**/test/**'] }],
      },
    });

    expect(config.disabledRules).toEqual(['RNSEC-SECRET-001']);
    expect(config.ruleOverrides[0]).toEqual({
      rule: 'RNSEC-LOG-001',
      severity: 'low',
      paths: ['**/test/**'],
    });
  });

  it('rejects an override that changes nothing', () => {
    expect(() => resolveConfig({ rules: { overrides: [{ rule: 'RNSEC-LOG-001' }] } })).toThrow(
      /changes nothing/
    );
  });

  it('refuses to pretend AI analysis ran, and says where AI actually lives', () => {
    // This package runs no model. AI assistance works the other way round: the
    // MCP server hands these findings to whichever model the developer already
    // uses. Accepting the flag would leave a project believing otherwise.
    expect(() => resolveConfig({ ai: { enabled: true } })).toThrow(/runs no AI analysis/);
    expect(() => resolveConfig({ ai: { enabled: true } })).toThrow(/docs\/mcp\.md/);
    expect(resolveConfig({ ai: { enabled: false } }).ai.enabled).toBe(false);
  });
});
