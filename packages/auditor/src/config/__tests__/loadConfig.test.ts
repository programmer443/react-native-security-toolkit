import { findConfigFile, loadConfig } from '../loadConfig.js';
import { AuditorConfigError } from '../resolveConfig.js';
import { TempProject } from '../../__tests__/helpers/tempProject.js';

/**
 * Configuration is read from a repository the auditor assumes is hostile.
 *
 * The tests that matter most here are the ones asserting what *does not*
 * happen: no import, no require, no evaluation. `await import(configPath)` would
 * hand control of the scanning process to the code being scanned, which is the
 * supply-chain problem this tool exists to warn about.
 */
describe('loadConfig', () => {
  let project: TempProject;

  beforeEach(() => {
    project = TempProject.create();
  });

  afterEach(() => {
    project.remove();
  });

  it('falls back to defaults when a project has no configuration file', async () => {
    const loaded = await loadConfig(project.root);

    expect(loaded.source).toBeUndefined();
    expect(loaded.config.profile).toBe('standard');
  });

  it('finds and reads a TypeScript configuration file', async () => {
    project.file(
      'security-toolkit.config.ts',
      [
        'export default {',
        "  profile: 'strict',",
        "  include: ['src/**'],",
        "  severity: { failOn: 'medium' },",
        '};',
      ].join('\n')
    );

    const loaded = await loadConfig(project.root);

    expect(loaded.source).toBe('security-toolkit.config.ts');
    expect(loaded.config.profile).toBe('strict');
    expect(loaded.config.include).toEqual(['src/**']);
    expect(loaded.config.failOn).toBe('medium');
  });

  it('reads the shape most people actually write', async () => {
    project.file(
      'security-toolkit.config.ts',
      [
        'import type { AuditorOptions } from "@rn-security/auditor";',
        '',
        'const config: AuditorOptions = {',
        "  profile: 'minimal',",
        '} as const;',
        '',
        'export default config;',
      ].join('\n')
    );

    const loaded = await loadConfig(project.root);

    expect(loaded.config.profile).toBe('minimal');
  });

  it('reads a CommonJS configuration file', async () => {
    project.file('security-toolkit.config.cjs', "module.exports = { profile: 'strict' };\n");

    const loaded = await loadConfig(project.root, project.path('security-toolkit.config.cjs'));

    expect(loaded.config.profile).toBe('strict');
  });

  it('reads a JSON configuration file', async () => {
    project.file('security-toolkit.config.json', JSON.stringify({ profile: 'minimal' }));

    const loaded = await loadConfig(project.root);

    expect(loaded.config.profile).toBe('minimal');
  });

  it('never executes the configuration file', async () => {
    // If this file were imported, the sentinel would exist. The statement is
    // simply not evaluated: only the default export is read, statically.
    project.file(
      'security-toolkit.config.ts',
      [
        "require('node:fs').writeFileSync(__dirname + '/EXECUTED', 'yes');",
        '',
        "export default { profile: 'strict' };",
      ].join('\n')
    );

    const loaded = await loadConfig(project.root);

    expect(loaded.config.profile).toBe('strict');
    expect(project.exists('EXECUTED')).toBe(false);
  });

  it('refuses a configuration value that cannot be evaluated statically', async () => {
    project.file(
      'security-toolkit.config.ts',
      'export default { include: [process.env.SECRET_GLOB] };\n'
    );

    await expect(loadConfig(project.root)).rejects.toThrow(AuditorConfigError);
    await expect(loadConfig(project.root)).rejects.toThrow(/statically analysable/);
  });

  it('refuses a computed key', async () => {
    project.file('security-toolkit.config.ts', 'export default { [`prof` + `ile`]: "strict" };\n');

    await expect(loadConfig(project.root)).rejects.toThrow(/computed key/);
  });

  it('refuses a function-valued option', async () => {
    project.file('security-toolkit.config.ts', 'export default { include: () => ["src"] };\n');

    await expect(loadConfig(project.root)).rejects.toThrow(/a function/);
  });

  it('explains a missing default export instead of silently using defaults', async () => {
    project.file('security-toolkit.config.ts', 'export const config = { profile: "strict" };\n');

    await expect(loadConfig(project.root)).rejects.toThrow(/no default export/);
  });

  it('reports a syntax error in the configuration file', async () => {
    project.file('security-toolkit.config.ts', 'export default { profile: ;\n');

    await expect(loadConfig(project.root)).rejects.toThrow(/could not be parsed/);
  });

  it('reports invalid JSON rather than falling back', async () => {
    project.file('security-toolkit.config.json', '{ profile: strict }');

    await expect(loadConfig(project.root)).rejects.toThrow(/not valid JSON/);
  });

  it('prefers the TypeScript configuration when several exist', async () => {
    project
      .file('security-toolkit.config.json', JSON.stringify({ profile: 'minimal' }))
      .file('security-toolkit.config.ts', "export default { profile: 'strict' };\n");

    expect(await findConfigFile(project.root)).toBe(project.path('security-toolkit.config.ts'));
  });

  it('evaluates spreads, templates and negative numbers, but nothing dynamic', async () => {
    project.file(
      'security-toolkit.config.ts',
      [
        "const shared = { profile: 'strict' };",
        'export default {',
        '  ...shared,',
        '  exclude: [`docs/**`],',
        '  limits: { maxFiles: 10 },',
        '};',
      ].join('\n')
    );

    const loaded = await loadConfig(project.root);

    expect(loaded.config.profile).toBe('strict');
    expect(loaded.config.exclude).toContain('docs/**');
    expect(loaded.config.limits.maxFiles).toBe(10);
  });
});
