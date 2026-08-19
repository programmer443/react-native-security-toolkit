/**
 * Manual mock for `react-native`, picked up automatically by Jest for modules
 * that live in `node_modules`.
 *
 * Loading the real React Native runtime under Jest buys nothing here: this
 * package touches exactly two of its APIs. A hand-written mock keeps the unit
 * tests fast, deterministic, and — importantly for a security package — able to
 * simulate platforms and a missing native module, which is the state a real
 * device is often in.
 */

const turboModules = new Map();

const Platform = {
  OS: 'ios',
  select: (specifics) =>
    Object.prototype.hasOwnProperty.call(specifics, Platform.OS)
      ? specifics[Platform.OS]
      : specifics.default,
};

const TurboModuleRegistry = {
  get: (name) => turboModules.get(name) ?? null,
  getEnforcing: (name) => {
    const module = turboModules.get(name);
    if (!module) {
      throw new Error(`TurboModuleRegistry.getEnforcing(...): '${name}' could not be found.`);
    }
    return module;
  },
};

/** Test helper: registers a fake TurboModule. */
function __setTurboModule(name, module) {
  if (module == null) {
    turboModules.delete(name);
  } else {
    turboModules.set(name, module);
  }
}

/** Test helper: restores the default platform and clears registered modules. */
function __resetReactNativeMock() {
  Platform.OS = 'ios';
  turboModules.clear();
}

module.exports = {
  Platform,
  TurboModuleRegistry,
  __setTurboModule,
  __resetReactNativeMock,
};
