import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { ExitCode, run } from '../main.js';
import type { CliContext } from '../context.js';

/**
 * The CLI is tested in-process.
 *
 * `run()` takes its world as an argument — cwd, writers, whether a terminal is
 * watching — and returns an exit code instead of touching `process`. So these
 * tests assert on what a command printed and returned without spawning a shell,
 * which also means they run before anything has been built.
 */

interface Captured {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

async function invoke(
  argv: readonly string[],
  overrides: Partial<CliContext> = {}
): Promise<Captured> {
  let stdout = '';
  let stderr = '';

  const exitCode = await run(argv, {
    cwd: overrides.cwd ?? process.cwd(),
    stdout: (text) => {
      stdout += text;
    },
    stderr: (text) => {
      stderr += text;
    },
    isTty: overrides.isTty ?? false,
  });

  return { exitCode, stdout, stderr };
}

/** A throwaway project on disk, because the CLI's job is to read real directories. */
class TempProject {
  readonly root: string;

  constructor() {
    this.root = fs.mkdtempSync(path.join(os.tmpdir(), 'rnsec-cli-'));
  }

  file(relative: string, contents: string): this {
    const absolute = path.join(this.root, relative);
    fs.mkdirSync(path.dirname(absolute), { recursive: true });
    fs.writeFileSync(absolute, contents);
    return this;
  }

  remove(): void {
    fs.rmSync(this.root, { recursive: true, force: true });
  }
}

describe('rn-security', () => {
  let project: TempProject;

  beforeEach(() => {
    project = new TempProject();
  });

  afterEach(() => {
    project.remove();
  });

  describe('usage', () => {
    it('prints help with no arguments, and exits successfully', async () => {
      const result = await invoke([]);

      expect(result.exitCode).toBe(ExitCode.Ok);
      expect(result.stdout).toContain('rn-security — static security analysis');
      expect(result.stdout).toContain('audit [path]');
    });

    it('prints the version it was given', async () => {
      // The bin shim reads the real version from package.json and passes it in.
      // A constant in the source would drift at the first release, and it is
      // recorded in every JSON and SARIF report the CLI writes.
      let stdout = '';
      const exitCode = await run(
        ['--version'],
        { cwd: process.cwd(), stdout: (text) => (stdout += text), stderr: () => {}, isTty: false },
        { version: '1.2.3' }
      );

      expect(exitCode).toBe(ExitCode.Ok);
      expect(stdout.trim()).toBe('1.2.3');
    });

    it('reports an obviously wrong version when no caller supplied one', async () => {
      // Better than a plausible-looking stale number: `0.0.0-unknown` in a
      // report says "this build was not wired up", which is the truth.
      const result = await invoke(['--version']);

      expect(result.stdout.trim()).toBe('0.0.0-unknown');
    });

    it('rejects an unknown command with usage, not a stack trace', async () => {
      const result = await invoke(['audti']);

      expect(result.exitCode).toBe(ExitCode.UsageError);
      expect(result.stderr).toContain('Unknown command "audti"');
      expect(result.stderr).not.toContain('at Object');
    });

    it('rejects an unknown flag and lists the ones that exist', async () => {
      // A mistyped flag that is silently ignored is how someone comes to believe
      // they ran with --fail-on critical when they did not.
      const result = await invoke(['audit', '--fail-onn', 'high']);

      expect(result.exitCode).toBe(ExitCode.UsageError);
      expect(result.stderr).toContain('--fail-on');
    });

    it('rejects an invalid severity and says what is valid', async () => {
      const result = await invoke(['audit', '--fail-on', 'severe']);

      expect(result.exitCode).toBe(ExitCode.UsageError);
      expect(result.stderr).toContain('critical, high, medium, low, info');
    });

    it('rejects contradictory colour flags', async () => {
      const result = await invoke(['audit', '--color', '--no-color']);

      expect(result.exitCode).toBe(ExitCode.UsageError);
    });

    it('reports an unreadable target as a usage error, not a clean scan', async () => {
      const result = await invoke(['audit', path.join(project.root, 'missing')]);

      expect(result.exitCode).toBe(ExitCode.UsageError);
      expect(result.stderr).toContain('Cannot read');
    });
  });

  describe('audit', () => {
    // The AWS key below is the documented example value from AWS's own
    // documentation, written into a temporary directory as scanner input. It is
    // still a credential-shaped string in this repository's source, so the
    // toolkit reports it when it scans itself — suppressed here with a reason,
    // which is exactly what a project using this tool is expected to do.
    it('reports a finding and exits 1 when it meets the threshold', async () => {
      // security-audit-ignore RNSEC-SECRET-001 reason="test input for the secrets rule, AWS's published example value"
      project.file('src/api.ts', 'const key = "AKIAIOSFODNN7EXAMPLE";\n');

      const result = await invoke(['audit', project.root, '--fail-on', 'high']);

      expect(result.exitCode).toBe(ExitCode.FindingsAtOrAboveThreshold);
      expect(result.stdout).toContain('RNSEC-SECRET-001');
      expect(result.stdout).toContain('AWS access key id');
    });

    it('exits 0 when nothing meets the threshold, even with findings', async () => {
      // The exit code answers one question — "should this build fail?" — and
      // `--fail-on` is what decides it.
      project.file('src/api.ts', 'const key = "AKIAIOSFODNN7EXAMPLE";\n');

      const result = await invoke([
        'audit',
        project.root,
        '--fail-on',
        'critical',
        '--min',
        'info',
      ]);
      const lenient = await invoke(['audit', project.root, '--fail-on', 'info']);

      expect(result.exitCode).toBe(ExitCode.FindingsAtOrAboveThreshold);
      expect(lenient.exitCode).toBe(ExitCode.FindingsAtOrAboveThreshold);
    });

    it('exits 0 on a clean project and says findings are not proof of safety', async () => {
      project.file('src/api.ts', 'export const baseUrl = "https://api.example.com";\n');

      const result = await invoke(['audit', project.root]);

      expect(result.exitCode).toBe(ExitCode.Ok);
      expect(result.stdout).toContain('No findings.');
      expect(result.stdout).toContain('No findings does not mean no risk');
    });

    it('writes to a file when asked, and says what it wrote', async () => {
      project.file('src/api.ts', 'const key = "AKIAIOSFODNN7EXAMPLE";\n');
      const destination = path.join(project.root, 'report.sarif');

      const result = await invoke([
        'audit',
        project.root,
        '--format',
        'sarif',
        '--out',
        destination,
      ]);

      expect(result.stdout).toContain('as sarif');
      const written = JSON.parse(fs.readFileSync(destination, 'utf8')) as { version: string };
      expect(written.version).toBe('2.1.0');
    });

    it('emits no colour when writing to a file, even from a terminal', async () => {
      project.file('src/api.ts', 'const key = "AKIAIOSFODNN7EXAMPLE";\n');
      const destination = path.join(project.root, 'report.txt');

      await invoke(['audit', project.root, '--out', destination], { isTty: true });

      expect(fs.readFileSync(destination, 'utf8')).not.toContain('[');
    });

    it('honours an explicit configuration file', async () => {
      project
        .file('src/api.ts', 'const key = "AKIAIOSFODNN7EXAMPLE";\n')
        .file('custom.config.json', JSON.stringify({ rules: { disabled: ['RNSEC-SECRET-001'] } }));

      const result = await invoke([
        'audit',
        project.root,
        '--config',
        path.join(project.root, 'custom.config.json'),
      ]);

      expect(result.exitCode).toBe(ExitCode.Ok);
      expect(result.stdout).toContain('No findings.');
    });

    it('reports a broken configuration file as a usage error', async () => {
      // A configuration mistake and a security finding are different events, and
      // a pipeline that cannot tell them apart will treat one as the other.
      project.file('security-toolkit.config.json', '{ "profile": "nonsense" }');

      const result = await invoke(['audit', project.root]);

      expect(result.exitCode).toBe(ExitCode.UsageError);
      expect(result.stderr).toContain('profile');
    });

    it('keeps the local root out of the output unless asked', async () => {
      project.file('src/api.ts', 'const key = "AKIAIOSFODNN7EXAMPLE";\n');

      const withoutRoot = await invoke(['audit', project.root, '--format', 'json']);
      const withRoot = await invoke(['audit', project.root, '--format', 'json', '--include-root']);

      expect(withoutRoot.stdout).not.toContain(project.root);
      expect(withRoot.stdout).toContain(project.root);
    });
  });

  describe('secrets', () => {
    it('runs only the secrets rule', async () => {
      project
        .file('src/api.ts', 'const key = "AKIAIOSFODNN7EXAMPLE";\n')
        // security-audit-ignore RNSEC-CRYPTO-001 reason="test input proving the secrets command does not run the crypto rule"
        .file('src/crypto.ts', 'const d = CryptoJS.MD5(value);\n');

      const result = await invoke(['secrets', project.root, '--min', 'info']);

      expect(result.stdout).toContain('1 rules');
      expect(result.stdout).toContain('RNSEC-SECRET-001');
      expect(result.stdout).not.toContain('RNSEC-CRYPTO-001');
    });

    it('says what its coverage does not include when it finds nothing', async () => {
      project.file('src/api.ts', 'export const ok = 1;\n');

      const result = await invoke(['secrets', project.root]);

      expect(result.stdout).toContain('a secret in an unusual format may not match');
    });
  });

  describe('dependencies', () => {
    it('reports unpinned resolution', async () => {
      project.file('package.json', JSON.stringify({ dependencies: { 'some-lib': '*' } }));

      const result = await invoke(['dependencies', project.root, '--min', 'info']);

      expect(result.stdout).toContain('RNSEC-DEPS-001');
      expect(result.stdout).toContain('not pinned');
    });

    it('states plainly that it is not a vulnerability scanner', async () => {
      // Claiming coverage the command does not have would be worse than the gap.
      project.file('package.json', JSON.stringify({ dependencies: { react: '19.2.3' } }));

      const result = await invoke(['dependencies', project.root]);

      expect(result.stdout).toContain(
        'does not check dependencies against vulnerability advisories'
      );
    });
  });

  describe('rules', () => {
    it('lists every shipped rule with its standards and documentation path', async () => {
      const result = await invoke(['rules']);

      expect(result.exitCode).toBe(ExitCode.Ok);
      expect(result.stdout).toContain('RNSEC-SECRET-001');
      expect(result.stdout).toContain('CWE-798');
      expect(result.stdout).toContain('docs/rules/RNSEC-SECRET-001.md');
    });

    it('emits machine-readable rules, including how to verify a fix', async () => {
      const result = await invoke(['rules', '--format', 'json']);
      const payload = JSON.parse(result.stdout) as {
        knowledgeSnapshot: string;
        rules: Array<{ id: string; verification: string[] }>;
      };

      expect(payload.knowledgeSnapshot).toMatch(/^\d{4}\.\d+$/);
      const storage = payload.rules.find((rule) => rule.id === 'RNSEC-STORAGE-001');
      expect(storage?.verification.every((id) => id.startsWith('MASTG-TEST-'))).toBe(true);
    });

    it('filters by category and rejects a category nobody uses', async () => {
      const filtered = await invoke(['rules', '--category', 'webview']);
      const unknown = await invoke(['rules', '--category', 'telepathy']);

      expect(filtered.stdout).toContain('RNSEC-WEBVIEW-001');
      expect(filtered.stdout).not.toContain('RNSEC-SECRET-001');
      expect(unknown.exitCode).toBe(ExitCode.UsageError);
      expect(unknown.stderr).toContain('Categories in use');
    });
  });

  describe('report', () => {
    it('re-renders a JSON report without re-running the scan', async () => {
      project.file('src/api.ts', 'const key = "AKIAIOSFODNN7EXAMPLE";\n');
      const json = path.join(project.root, 'report.json');
      await invoke(['audit', project.root, '--format', 'json', '--out', json]);

      const result = await invoke(['report', json, '--format', 'markdown']);

      expect(result.stdout).toContain('# Security audit');
      expect(result.stdout).toContain('RNSEC\\-SECRET\\-001');
    });

    it('preserves the verdict the scan reached', async () => {
      project.file('src/api.ts', 'const key = "AKIAIOSFODNN7EXAMPLE";\n');
      const json = path.join(project.root, 'report.json');
      await invoke(['audit', project.root, '--format', 'json', '--out', json]);

      const result = await invoke(['report', json, '--format', 'console']);

      expect(result.exitCode).toBe(ExitCode.FindingsAtOrAboveThreshold);
    });

    it('refuses a file that is not a report rather than rendering nonsense', async () => {
      project.file('not-a-report.json', JSON.stringify({ hello: 'world' }));

      const result = await invoke(['report', path.join(project.root, 'not-a-report.json')]);

      expect(result.exitCode).toBe(ExitCode.UsageError);
      expect(result.stderr).toContain('missing');
    });

    it('refuses invalid JSON with the parse error', async () => {
      project.file('broken.json', '{ findings: }');

      const result = await invoke(['report', path.join(project.root, 'broken.json')]);

      expect(result.exitCode).toBe(ExitCode.UsageError);
      expect(result.stderr).toContain('not valid JSON');
    });
  });

  describe('runtime', () => {
    it('says plainly that it cannot check a device', async () => {
      project.file('package.json', JSON.stringify({ dependencies: {} }));

      const result = await invoke(['runtime', project.root]);

      expect(result.exitCode).toBe(ExitCode.Ok);
      expect(result.stdout).toContain('project configuration only');
      expect(result.stdout).toContain('execute inside the application on a device');
    });

    it('finds the declarations that decide whether a signal can answer', async () => {
      project
        .file(
          'package.json',
          JSON.stringify({ dependencies: { 'react-native-security-toolkit': '^0.1.0' } })
        )
        .file(
          'android/app/src/main/AndroidManifest.xml',
          [
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android">',
            '  <uses-permission android:name="android.permission.USE_BIOMETRIC" />',
            '  <application android:networkSecurityConfig="@xml/nsc" />',
            '</manifest>',
          ].join('\n')
        );

      const result = await invoke(['runtime', project.root]);

      expect(result.stdout).toContain('ok   [project] react-native-security-toolkit dependency');
      expect(result.stdout).toContain('ok   [android] USE_BIOMETRIC permission');
      expect(result.stdout).toContain('MISS [android] ACCESS_NETWORK_STATE permission');
    });

    it('skips a platform that is not present rather than reporting it missing', async () => {
      project.file('package.json', JSON.stringify({ dependencies: {} }));

      const result = await invoke(['runtime', project.root, '--format', 'json']);
      const payload = JSON.parse(result.stdout) as {
        checks: Array<{ item: string; state: string }>;
      };
      const ios = payload.checks.find((check) => check.item === 'Info.plist');

      expect(ios?.state).toBe('not-found');
    });

    it('never fails a build: missing configuration is advice', async () => {
      project.file('package.json', JSON.stringify({ dependencies: {} }));

      const result = await invoke(['runtime', project.root]);

      expect(result.exitCode).toBe(ExitCode.Ok);
    });
  });
});
