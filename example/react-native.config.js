const path = require('path');
const pkg = require('../packages/runtime/package.json');

module.exports = {
  project: {
    ios: {
      automaticPodsInstallation: true,
    },
  },
  dependencies: {
    [pkg.name]: {
      root: path.join(__dirname, '..', 'packages', 'runtime'),
      platforms: {
        // The codegen script fails without an explicit (if empty) platform entry.
        ios: {},
        android: {},
      },
    },
  },
};
