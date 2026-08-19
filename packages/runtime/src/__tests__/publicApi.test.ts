import * as publicApi from '../index';

/**
 * The public surface is a promise to consumers, so it is asserted explicitly
 * rather than left to drift. Adding an export is a deliberate act that updates
 * this list; §50 of the brief calls for a small, intentional API.
 */
describe('public API surface', () => {
  it('exports exactly the intended runtime values', () => {
    expect(Object.keys(publicApi).sort()).toEqual([
      'BiometricSecurity',
      'DebuggerDetection',
      'EmulatorDetection',
      'HookDetection',
      'IntegrityCheck',
      'JailbreakDetection',
      'NetworkSecurity',
      'RISK_METHODOLOGY_VERSION',
      'RootDetection',
      'ScreenSecurity',
      'SecureHardware',
      'SecurityToolkit',
      'SecurityToolkitError',
      'SimulatorDetection',
      'evaluateRisk',
      'isSecurityToolkitError',
    ]);
  });

  it('exposes only the intended methods on SecurityToolkit', () => {
    expect(Object.keys(publicApi.SecurityToolkit).sort()).toEqual([
      'checkAll',
      'configure',
      'evaluate',
      'getConfiguration',
      'getEngineInfo',
      'getPlatform',
      'isAvailable',
      'resetConfiguration',
    ]);
  });

  it('exposes only getStatus on a plain check facade', () => {
    expect(Object.keys(publicApi.RootDetection)).toEqual(['getStatus']);
  });

  it('exposes documented convenience methods where the brief calls for them', () => {
    expect(Object.keys(publicApi.DebuggerDetection).sort()).toEqual(['getStatus', 'isAttached']);
    expect(Object.keys(publicApi.EmulatorDetection).sort()).toEqual(['getStatus', 'isEmulator']);
    expect(Object.keys(publicApi.SimulatorDetection).sort()).toEqual(['getStatus', 'isSimulator']);
    expect(Object.keys(publicApi.ScreenSecurity).sort()).toEqual([
      'disableProtection',
      'enableProtection',
      'getStatus',
    ]);
  });

  it('does not leak internal test seams', () => {
    expect(publicApi).not.toHaveProperty('__setNativeModuleForTesting');
  });

  it('does not expose an API that would encourage overclaiming', () => {
    // No `isSecure`, no `blockIfCompromised`: the toolkit reports, the app decides.
    const surface = Object.keys(publicApi.SecurityToolkit).join(' ').toLowerCase();
    expect(surface).not.toMatch(/issecure|block|terminate|kill/);
  });
});
