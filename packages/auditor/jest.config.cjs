/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: 'node',
  rootDir: '.',
  moduleFileExtensions: ['ts', 'js', 'json'],
  testMatch: ['<rootDir>/src/**/__tests__/**/*.test.ts'],
  // Source is ESM with explicit `.js` specifiers, as `moduleResolution: nodenext`
  // requires. Jest resolves the on-disk TypeScript, so the extension is mapped away.
  moduleNameMapper: { '^(\\.{1,2}/.*)\\.js$': '$1' },
  collectCoverageFrom: ['src/**/*.ts', '!src/**/__tests__/**', '!src/types/**'],
  coverageThreshold: {
    global: { statements: 90, branches: 85, functions: 90, lines: 90 },
  },
};
