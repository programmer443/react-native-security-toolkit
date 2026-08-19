import { defaultLimits } from '../../config/defaults.js';
import { DEFAULT_EXCLUDE } from '../../config/defaults.js';
import { discoverFiles } from '../discoverFiles.js';
import { TempProject } from '../../__tests__/helpers/tempProject.js';
import type { DiscoveryResult } from '../discoverFiles.js';
import type { ScanLimits } from '../../types/config.js';

/**
 * Discovery against repositories that are trying to cause trouble.
 *
 * Every case here is something a real repository can contain, whether by malice
 * or by accident, and every one of them breaks a naive `readdir` walk.
 */
describe('discoverFiles', () => {
  let project: TempProject;

  beforeEach(() => {
    project = TempProject.create();
  });

  afterEach(() => {
    project.remove();
  });

  function scan(
    overrides: Partial<ScanLimits> = {},
    include: string[] = []
  ): Promise<DiscoveryResult> {
    return discoverFiles({
      root: project.root,
      include,
      exclude: [...DEFAULT_EXCLUDE],
      limits: { ...defaultLimits(), ...overrides },
    });
  }

  it('finds project files and reports them with project-relative POSIX paths', async () => {
    project
      .file('src/index.ts', 'export const a = 1;\n')
      .file('android/app/build.gradle', '// build\n');

    const result = await scan();

    expect(result.files.map((file) => file.path)).toEqual([
      'android/app/build.gradle',
      'src/index.ts',
    ]);
    expect(result.files[0]?.kind).toBe('gradle-build');
    expect(result.truncated).toBe(false);
  });

  it('never follows a symbolic link, and records that it did not', async () => {
    // A link to an absolute path outside the project turns a secrets scan into
    // an exfiltration tool the moment the report is uploaded.
    project.file('src/index.ts', 'export const a = 1;\n').symlink('src/escape.ts', '/etc/passwd');

    const result = await scan();

    expect(result.files.map((file) => file.path)).toEqual(['src/index.ts']);
    expect(result.skipped).toContainEqual(
      expect.objectContaining({ path: 'src/escape.ts', reason: 'symbolic-link' })
    );
  });

  it('does not hang on a symbolic link loop', async () => {
    project.dir('src').symlink('src/loop', project.root).file('src/index.ts', 'export {};\n');

    const result = await scan();

    expect(result.files.map((file) => file.path)).toEqual(['src/index.ts']);
    expect(result.skipped).toContainEqual(
      expect.objectContaining({ path: 'src/loop', reason: 'symbolic-link' })
    );
  });

  it('skips a file larger than the per-file limit and says how large it was', async () => {
    project.file('src/huge.ts', 'x'.repeat(5_000)).file('src/small.ts', 'export {};\n');

    const result = await scan({ maxFileBytes: 1_000 });

    expect(result.files.map((file) => file.path)).toEqual(['src/small.ts']);
    const skipped = result.skipped.find((entry) => entry.path === 'src/huge.ts');
    expect(skipped?.reason).toBe('too-large');
    expect(skipped?.detail).toContain('5000');
  });

  it('skips binary files by extension without reading them', async () => {
    project.file('android/app/libs/native.so', Buffer.from([0, 1, 2, 3]));

    const result = await scan();

    expect(result.files).toHaveLength(0);
    expect(result.skipped).toContainEqual(
      expect.objectContaining({ path: 'android/app/libs/native.so', reason: 'binary' })
    );
  });

  it('stops at the file limit, records where it stopped, and marks the scan truncated', async () => {
    for (let index = 0; index < 10; index += 1) {
      project.file(`src/file${index}.ts`, 'export {};\n');
    }

    const result = await scan({ maxFiles: 3 });

    expect(result.files).toHaveLength(3);
    expect(result.truncated).toBe(true);
    expect(result.skipped.some((entry) => entry.reason === 'file-limit-reached')).toBe(true);
  });

  it('stops at the total byte budget rather than reading a project of any size', async () => {
    project
      .file('src/a.ts', 'x'.repeat(400))
      .file('src/b.ts', 'x'.repeat(400))
      .file('src/c.ts', 'x'.repeat(400));

    const result = await scan({ maxTotalBytes: 900 });

    expect(result.files.length).toBeLessThan(3);
    expect(result.truncated).toBe(true);
    expect(result.skipped.some((entry) => entry.reason === 'total-size-limit-reached')).toBe(true);
  });

  it('stops descending at the depth limit instead of overflowing the stack', async () => {
    project.file(`${'nested/'.repeat(30)}deep.ts`, 'export {};\n');

    const result = await scan({ maxDepth: 5 });

    expect(result.files).toHaveLength(0);
    expect(result.truncated).toBe(true);
    expect(result.skipped.some((entry) => entry.reason === 'depth-limit-reached')).toBe(true);
  });

  it('prunes excluded directories rather than walking into them', async () => {
    project
      .file('node_modules/left-pad/index.js', 'module.exports = 1;\n')
      .file('ios/Pods/Firebase/Firebase.h', '// pod\n')
      .file('src/index.ts', 'export {};\n');

    const result = await scan();

    expect(result.files.map((file) => file.path)).toEqual(['src/index.ts']);
    // Configuration-driven skips are counted, not listed: nobody needs forty
    // thousand lines telling them node_modules was excluded.
    expect(result.excludedCount).toBeGreaterThan(0);
    expect(result.skipped).toHaveLength(0);
  });

  it('honours include patterns and counts what they left out', async () => {
    project.file('src/index.ts', 'export {};\n').file('scripts/build.ts', 'export {};\n');

    const result = await scan({}, ['src/**']);

    expect(result.files.map((file) => file.path)).toEqual(['src/index.ts']);
    expect(result.notIncludedCount).toBe(1);
  });

  it('produces the same ordering on every run', async () => {
    project
      .file('src/b.ts', 'export {};\n')
      .file('src/a.ts', 'export {};\n')
      .file('src/c.ts', 'export {};\n');

    const first = await scan();
    const second = await scan();

    expect(first.files.map((file) => file.path)).toEqual(second.files.map((file) => file.path));
    expect(first.files.map((file) => file.path)).toEqual(['src/a.ts', 'src/b.ts', 'src/c.ts']);
  });

  it('records an unreadable directory instead of failing the scan', async () => {
    project.file('src/index.ts', 'export {};\n').dir('locked');
    const fs = await import('node:fs');
    fs.chmodSync(project.path('locked'), 0o000);

    try {
      const result = await scan();

      expect(result.files.map((file) => file.path)).toEqual(['src/index.ts']);
      expect(result.skipped).toContainEqual(
        expect.objectContaining({ path: 'locked', reason: 'unreadable' })
      );
    } finally {
      fs.chmodSync(project.path('locked'), 0o700);
    }
  });
});
