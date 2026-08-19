/**
 * Babel configuration used by Jest only. The published build is produced by
 * `tsc`, which does not read this file.
 */
module.exports = {
  presets: [['@babel/preset-env', { targets: { node: 'current' } }], '@babel/preset-typescript'],
};
