const path = require('path');
const { getConfig } = require('react-native-builder-bob/babel-config');

// The library lives in `packages/runtime`, not at the repository root, so point
// builder-bob's Babel config at that package's manifest — the workspace root
// manifest has no `react-native-builder-bob` field.
const pkg = require('../packages/runtime/package.json');
const root = path.resolve(__dirname, '..', 'packages', 'runtime');

module.exports = getConfig(
  {
    presets: ['module:@react-native/babel-preset'],
  },
  { root, pkg }
);
