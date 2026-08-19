import { fixupConfigRules } from '@eslint/compat';
import { FlatCompat } from '@eslint/eslintrc';
import js from '@eslint/js';
import prettier from 'eslint-plugin-prettier';
import { defineConfig } from 'eslint/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const compat = new FlatCompat({
  baseDirectory: __dirname,
  recommendedConfig: js.configs.recommended,
  allConfig: js.configs.all,
});

export default defineConfig([
  {
    // Jest setup files run in the test environment, not application code.
    files: ['**/jest.setup.js', '**/jest.config.js', '**/__mocks__/**/*.js'],
    languageOptions: {
      globals: {
        beforeEach: 'readonly',
        afterEach: 'readonly',
        jest: 'readonly',
        module: 'writable',
        require: 'readonly',
      },
    },
  },
  {
    ignores: [
      '**/node_modules/**',
      '**/lib/**',
      '**/dist/**',
      // Deliberately insecure code, kept as scanner input rather than as source.
      'fixtures/**',
      // Generated from the official OWASP and MITRE sources, never hand-edited.
      '**/knowledge/snapshots/**',
      '**/build/**',
      '**/coverage/**',
      '**/generated/**',
      '**/Pods/**',
      '**/vendor/**',
    ],
  },
  {
    extends: fixupConfigRules(compat.extends('@react-native', 'prettier')),
    plugins: { prettier },
    rules: {
      'react/react-in-jsx-scope': 'off',
      'prettier/prettier': 'error',
    },
  },
  {
    // Config and tooling files in this repository are ES modules.
    files: ['**/*.mjs'],
    languageOptions: {
      sourceType: 'module',
      ecmaVersion: 'latest',
      globals: {
        Buffer: 'readonly',
        URL: 'readonly',
        console: 'readonly',
        fetch: 'readonly',
        process: 'readonly',
        setTimeout: 'readonly',
      },
    },
  },
  {
    // Security-sensitive source: the escape hatches this project bans (§70/§71).
    files: ['packages/**/src/**/*.ts', 'packages/**/src/**/*.tsx'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/ban-ts-comment': [
        'error',
        { 'ts-ignore': true, 'ts-expect-error': 'allow-with-description' },
      ],
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-console': ['error', { allow: ['warn', 'error'] }],
      // TypeScript's `noPropertyAccessFromIndexSignature` requires bracket
      // notation for index-signature reads, which is exactly how untrusted
      // native payloads are accessed. The two rules contradict each other;
      // the compiler wins.
      'dot-notation': 'off',
    },
  },
  {
    files: ['**/__tests__/**/*.ts', '**/*.test.ts'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },
]);
