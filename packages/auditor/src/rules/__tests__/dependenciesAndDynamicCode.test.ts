import { dynamicCodeExecutionRule } from '../reactNative/dynamicCodeExecution.js';
import { untrustedDependencyRule } from '../dependencies/untrustedDependency.js';
import { runRule } from './helpers/runRule.js';

describe('RNSEC-DEPS-001 dependency from an unpinned or unauthenticated source', () => {
  describe('true positives', () => {
    it('reports a wildcard version', async () => {
      const findings = await runRule(
        untrustedDependencyRule,
        'package.json',
        JSON.stringify({ dependencies: { 'some-lib': '*' } }, null, 2)
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.title).toContain('not pinned');
    });

    it('reports a git dependency fetched without transport authentication', async () => {
      const findings = await runRule(
        untrustedDependencyRule,
        'package.json',
        JSON.stringify(
          { dependencies: { 'internal-lib': 'git://github.com/acme/lib.git' } },
          null,
          2
        )
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.severity).toBe('high');
    });

    it('reports a git dependency with no commit pin', async () => {
      const findings = await runRule(
        untrustedDependencyRule,
        'package.json',
        JSON.stringify({ dependencies: { 'internal-lib': 'github:acme/lib#main' } }, null, 2)
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.title).toContain('commit pin');
    });
  });

  describe('true negatives', () => {
    it('says nothing about ordinary semver ranges', async () => {
      // Ranges plus a committed lockfile are how the ecosystem works; flagging
      // them would be noise.
      const findings = await runRule(
        untrustedDependencyRule,
        'package.json',
        JSON.stringify(
          { dependencies: { react: '19.2.3', 'react-native': '^0.87.0', zod: '~3.24.1' } },
          null,
          2
        )
      );

      expect(findings).toEqual([]);
    });

    it('says nothing about a git dependency pinned to a commit', async () => {
      const findings = await runRule(
        untrustedDependencyRule,
        'package.json',
        JSON.stringify(
          {
            dependencies: {
              'internal-lib':
                'git+https://github.com/acme/lib.git#4f2c1a9d8e7b6c5a4f3e2d1c0b9a8f7e6d5c4b3a',
            },
          },
          null,
          2
        )
      );

      expect(findings).toEqual([]);
    });
  });

  describe('edge cases', () => {
    it('allows a wildcard in peerDependencies, where it is a compatibility statement', async () => {
      const findings = await runRule(
        untrustedDependencyRule,
        'package.json',
        JSON.stringify({ peerDependencies: { react: '*', 'react-native': '*' } }, null, 2)
      );

      expect(findings).toEqual([]);
    });

    it('says nothing about a manifest that is not valid JSON', async () => {
      // A broken manifest is a build problem, and the toolchain will say so.
      const findings = await runRule(untrustedDependencyRule, 'package.json', '{ dependencies: }');

      expect(findings).toEqual([]);
    });
  });

  describe('false positives it must not produce', () => {
    it('does not scan lockfiles or arbitrary JSON', async () => {
      expect(untrustedDependencyRule.fileKinds).toEqual(['package-manifest']);
    });

    it('ignores workspace and file protocols used inside a monorepo', async () => {
      const findings = await runRule(
        untrustedDependencyRule,
        'package.json',
        JSON.stringify(
          { dependencies: { '@app/core': 'workspace:*', '@app/ui': 'file:../ui' } },
          null,
          2
        )
      );

      expect(findings).toEqual([]);
    });
  });
});

describe('RNSEC-RN-001 dynamic code execution', () => {
  describe('true positives', () => {
    it('reports eval', async () => {
      const findings = await runRule(dynamicCodeExecutionRule, 'src/plugins.ts', 'eval(payload);');

      expect(findings).toHaveLength(1);
      expect(findings[0]?.severity).toBe('critical');
    });

    it('reports the Function constructor in both forms', async () => {
      const findings = await runRule(
        dynamicCodeExecutionRule,
        'src/plugins.ts',
        ['const a = new Function("return " + expr);', 'const b = Function("return 1")();'].join(
          '\n'
        )
      );

      expect(findings).toHaveLength(2);
    });

    it('reports a timer given code as a string', async () => {
      const findings = await runRule(
        dynamicCodeExecutionRule,
        'src/plugins.ts',
        'setTimeout("refresh()", 1000);'
      );

      expect(findings).toHaveLength(1);
    });
  });

  describe('true negatives', () => {
    it('says nothing about ordinary timers and JSON parsing', async () => {
      const findings = await runRule(
        dynamicCodeExecutionRule,
        'src/plugins.ts',
        ['setTimeout(() => refresh(), 1000);', 'const config = JSON.parse(body);'].join('\n')
      );

      expect(findings).toEqual([]);
    });
  });

  describe('edge cases', () => {
    it('reports eval reached through the global object', async () => {
      const findings = await runRule(
        dynamicCodeExecutionRule,
        'src/plugins.ts',
        'global.eval(payload);'
      );

      expect(findings).toHaveLength(1);
    });
  });

  describe('false positives it must not produce', () => {
    it('ignores a method that merely happens to be called evaluate', async () => {
      const findings = await runRule(
        dynamicCodeExecutionRule,
        'src/rules.ts',
        'const result = policy.evaluate(context);'
      );

      expect(findings).toEqual([]);
    });

    it('ignores a variable named eval in another object', async () => {
      const findings = await runRule(
        dynamicCodeExecutionRule,
        'src/rules.ts',
        'const outcome = interpreter.eval;'
      );

      expect(findings).toEqual([]);
    });
  });
});
