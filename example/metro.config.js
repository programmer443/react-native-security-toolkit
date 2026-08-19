const fs = require('node:fs');
const path = require('node:path');
const { getDefaultConfig } = require('@react-native/metro-config');
const { withMetroConfig } = require('react-native-monorepo-config');

// Workspace root, so Metro watches packages/runtime as well as the example app.
const root = path.resolve(__dirname, '..');

/**
 * `react-native-monorepo-config` expects a Yarn/npm-style `workspaces` field in
 * the root `package.json`. This workspace is defined by `pnpm-workspace.yaml`
 * instead, so the patterns are read from there — one source of truth, and no
 * YAML dependency for a five-line list.
 */
function readWorkspacePatterns() {
  const lines = fs.readFileSync(path.join(root, 'pnpm-workspace.yaml'), 'utf8').split('\n');

  const start = lines.findIndex((line) => /^packages:\s*$/.test(line));

  if (start === -1) {
    throw new Error("No 'packages:' list found in pnpm-workspace.yaml");
  }

  const patterns = [];

  for (const line of lines.slice(start + 1)) {
    const entry = line.match(/^\s+-\s*['"]?(.+?)['"]?\s*$/);

    if (entry !== null) {
      patterns.push(entry[1]);
    } else if (/^\S/.test(line)) {
      break; // Start of the next top-level key.
    }
  }

  if (patterns.length === 0) {
    throw new Error("The 'packages:' list in pnpm-workspace.yaml is empty");
  }

  return patterns;
}

/**
 * Metro configuration
 * https://facebook.github.io/metro/docs/configuration
 *
 * @type {import('metro-config').MetroConfig}
 */
const config = withMetroConfig(getDefaultConfig(__dirname), {
  root,
  dirname: __dirname,
  workspaces: readWorkspacePatterns(),
  conditions: ['react-native-security-toolkit-source'],
});

module.exports = config;
