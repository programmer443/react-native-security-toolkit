import { isDirectoryExcluded, matchesAnyGlob, matchesGlob } from '../glob.js';

describe('glob matching', () => {
  it('matches a single segment with * and never crosses a separator', () => {
    expect(matchesGlob('src/index.ts', 'src/*.ts')).toBe(true);
    expect(matchesGlob('src/nested/index.ts', 'src/*.ts')).toBe(false);
  });

  it('matches any number of segments with **, including none', () => {
    expect(matchesGlob('src/index.ts', 'src/**/index.ts')).toBe(true);
    expect(matchesGlob('src/a/b/index.ts', 'src/**/index.ts')).toBe(true);
    expect(matchesGlob('src/a/b/c.ts', '**/*.ts')).toBe(true);
  });

  it('expands brace alternatives', () => {
    expect(matchesGlob('src/App.tsx', '**/*.{ts,tsx}')).toBe(true);
    expect(matchesGlob('src/App.js', '**/*.{ts,tsx}')).toBe(false);
  });

  it('matches a slash-free pattern against the final segment, wherever it appears', () => {
    expect(matchesGlob('android/app/proguard.log', '*.log')).toBe(true);
    expect(matchesGlob('ios/Podfile', 'Podfile')).toBe(true);
  });

  it('treats regular expression metacharacters in a pattern as literals', () => {
    // A pattern is not a regular expression. `.` must match a dot and nothing
    // else, or an exclusion silently covers far more than it says.
    expect(matchesGlob('srcXindex.ts', 'src.index.ts')).toBe(false);
    expect(matchesGlob('src.index.ts', 'src.index.ts')).toBe(true);
    expect(matchesGlob('a+b/c.ts', 'a+b/*.ts')).toBe(true);
  });

  it('does not match anything when there are no patterns', () => {
    expect(matchesAnyGlob('src/index.ts', [])).toBe(false);
  });

  describe('directory pruning', () => {
    it('prunes a directory named by a trailing-globstar pattern', () => {
      expect(isDirectoryExcluded('node_modules', ['**/node_modules/**'])).toBe(true);
      expect(isDirectoryExcluded('example/node_modules', ['**/node_modules/**'])).toBe(true);
    });

    it('leaves unrelated directories alone', () => {
      expect(isDirectoryExcluded('src', ['**/node_modules/**'])).toBe(false);
      // Pruning must not be fooled by a prefix: `node_modules_backup` is a
      // different directory and its contents are the project's own.
      expect(isDirectoryExcluded('node_modules_backup', ['**/node_modules/**'])).toBe(false);
    });
  });

  it('terminates promptly on a pattern with many wildcards', () => {
    // Adversarial patterns are the reason this matcher exists rather than a
    // dependency. Nested quantifiers are what make a glob library hang.
    const pattern = `${'*/'.repeat(40)}*.ts`;
    const start = Date.now();
    expect(matchesGlob(`${'a/'.repeat(40)}b.tsx`, pattern)).toBe(false);
    expect(Date.now() - start).toBeLessThan(1_000);
  });
});
