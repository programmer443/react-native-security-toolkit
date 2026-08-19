import {
  classifyFile,
  fileKindOf,
  isExamplePath,
  isFixturePath,
  isTestPath,
  languageOf,
} from '../classify.js';

describe('language detection', () => {
  it.each([
    ['src/index.ts', 'typescript'],
    ['src/App.tsx', 'tsx'],
    ['src/legacy.js', 'javascript'],
    ['src/legacy.jsx', 'jsx'],
    ['android/src/main/java/com/app/Main.kt', 'kotlin'],
    ['ios/AppDelegate.swift', 'swift'],
    ['ios/Bridge.mm', 'objective-cpp'],
    ['android/app/src/main/AndroidManifest.xml', 'xml'],
    ['ios/App/Info.plist', 'plist'],
    ['android/app/build.gradle', 'gradle'],
    ['ios/Podfile', 'unknown'],
  ])('classifies %s as %s', (path, expected) => {
    expect(languageOf(path)).toBe(expected);
  });

  it('reports an unrecognised extension as unknown rather than guessing', () => {
    expect(languageOf('assets/data.bespoke')).toBe('unknown');
  });
});

describe('file kind', () => {
  it.each([
    ['android/app/src/main/AndroidManifest.xml', 'android-manifest'],
    ['android/app/build.gradle', 'gradle-build'],
    ['ios/Podfile', 'podfile'],
    ['ios/Podfile.lock', 'podfile-lock'],
    ['package.json', 'package-manifest'],
    ['pnpm-lock.yaml', 'lockfile'],
    ['metro.config.js', 'metro-config'],
    ['app.json', 'expo-config'],
    ['.env.production', 'env-file'],
    ['ios/App/App.entitlements', 'ios-entitlements'],
    ['ios/App/Info.plist', 'ios-plist'],
    ['src/api/client.ts', 'source'],
    ['README.md', 'documentation'],
  ])('classifies %s as %s', (path, expected) => {
    expect(fileKindOf(path)).toBe(expected);
  });

  it('detects an Android network security config by its location and name', () => {
    expect(fileKindOf('android/app/src/main/res/xml/network_security_config.xml')).toBe(
      'android-network-security-config'
    );
  });

  it('classifies fixture and test files before applying the name table', () => {
    // A package.json inside a fixture directory is test data. Treating it as the
    // project's dependency manifest is how a scanner reports the vulnerabilities
    // it was deliberately handed as input.
    expect(fileKindOf('src/__fixtures__/vulnerable/package.json')).toBe('fixture');
    expect(fileKindOf('src/__tests__/client.test.ts')).toBe('test');
  });
});

describe('path context', () => {
  it('recognises test paths in every layout the ecosystem uses', () => {
    expect(isTestPath('src/__tests__/a.ts')).toBe(true);
    expect(isTestPath('src/a.test.ts')).toBe(true);
    expect(isTestPath('src/a.spec.tsx')).toBe(true);
    expect(isTestPath('android/src/test/java/com/app/RootDetectorsTest.kt')).toBe(true);
    expect(isTestPath('src/api/client.ts')).toBe(false);
  });

  it('recognises fixtures, mocks and snapshots', () => {
    expect(isFixturePath('src/__mocks__/react-native.js')).toBe(true);
    expect(isFixturePath('fixtures/vulnerable-android/App.kt')).toBe(true);
    expect(isFixturePath('src/api/client.ts')).toBe(false);
  });

  it('recognises example applications', () => {
    expect(isExamplePath('example/src/App.tsx')).toBe(true);
    expect(isExamplePath('src/example.ts')).toBe(false);
  });
});

describe('classifyFile', () => {
  it('returns language and kind together', () => {
    expect(classifyFile('src/App.tsx')).toEqual({ language: 'tsx', kind: 'source' });
  });
});
