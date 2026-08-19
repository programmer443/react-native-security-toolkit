const { __resetReactNativeMock } = require('react-native');

// Each test starts from the same platform and an unlinked native module, so no
// test can pass because a previous one left state behind.
beforeEach(() => {
  __resetReactNativeMock();
});
