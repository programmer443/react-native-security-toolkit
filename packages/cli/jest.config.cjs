/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: 'node',
  rootDir: '.',
  moduleFileExtensions: ['ts', 'js', 'json'],
  testMatch: ['<rootDir>/src/**/__tests__/**/*.test.ts'],
  // Source is ESM with explicit `.js` specifiers, as `moduleResolution: nodenext`
  // requires. Jest resolves the on-disk TypeScript, so the extension is mapped away.
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
    // Resolve the workspace dependency to its source, so a CLI test fails when
    // the auditor changes rather than passing against a stale build.
    '^@rn-security/auditor$': '<rootDir>/../auditor/src/index.ts',
  },
  collectCoverageFrom: ['src/**/*.ts', '!src/**/__tests__/**', '!src/types/**'],
  coverageThreshold: {
    global: { statements: 90, branches: 85, functions: 90, lines: 90 },
  },
};
