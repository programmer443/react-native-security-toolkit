/**
 * Babel configuration used by Jest only. The published build is produced by
 * react-native-builder-bob, which uses the repository-root configuration.
 */
module.exports = {
  presets: [['@babel/preset-env', { targets: { node: 'current' } }], '@babel/preset-typescript'],
};
