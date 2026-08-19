import { insecureStorageRule } from '../storage/insecureStorage.js';
import { runRule } from './helpers/runRule.js';

describe('RNSEC-STORAGE-001 sensitive data in unencrypted storage', () => {
  describe('true positives', () => {
    it('reports a token written to AsyncStorage', async () => {
      const findings = await runRule(
        insecureStorageRule,
        'src/auth/session.ts',
        'await AsyncStorage.setItem("refreshToken", refreshToken);'
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.confidence).toBe('high');
      expect(findings[0]?.severity).toBe('high');
    });

    it('reports when only the value name is sensitive', async () => {
      const findings = await runRule(
        insecureStorageRule,
        'src/auth/session.ts',
        'await AsyncStorage.setItem("user-state", accessToken);'
      );

      expect(findings).toHaveLength(1);
      // One half of the evidence rather than both.
      expect(findings[0]?.confidence).toBe('medium');
    });

    it('reports a credential written to SharedPreferences', async () => {
      const findings = await runRule(
        insecureStorageRule,
        'android/app/src/main/java/com/app/Store.kt',
        'prefs.edit().putString("password", password).apply()'
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.title).toContain('SharedPreferences');
    });

    it('reports a token written to UserDefaults', async () => {
      const findings = await runRule(
        insecureStorageRule,
        'ios/Session.swift',
        'UserDefaults.standard.set(accessToken, forKey: "accessToken")'
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.title).toContain('UserDefaults');
    });
  });

  describe('true negatives', () => {
    it('says nothing about preferences, which are what AsyncStorage is for', async () => {
      // §34 is explicit: not every AsyncStorage call is a vulnerability.
      const findings = await runRule(
        insecureStorageRule,
        'src/settings.ts',
        [
          'await AsyncStorage.setItem("theme", "dark");',
          'await AsyncStorage.setItem("onboardingComplete", "true");',
          'await AsyncStorage.setItem("lastSyncedAt", String(Date.now()));',
        ].join('\n')
      );

      expect(findings).toEqual([]);
    });

    it('says nothing when the file uses encrypted storage', async () => {
      const findings = await runRule(
        insecureStorageRule,
        'src/auth/session.ts',
        [
          'import * as SecureStore from "expo-secure-store";',
          'await SecureStore.setItemAsync("refreshToken", refreshToken);',
        ].join('\n')
      );

      expect(findings).toEqual([]);
    });

    it('says nothing about EncryptedSharedPreferences', async () => {
      const findings = await runRule(
        insecureStorageRule,
        'android/app/src/main/java/com/app/Store.kt',
        [
          'val prefs = EncryptedSharedPreferences.create(context, "secure", masterKey, scheme, scheme)',
          'prefs.edit().putString("accessToken", accessToken).apply()',
        ].join('\n')
      );

      expect(findings).toEqual([]);
    });
  });

  describe('edge cases', () => {
    it('reads a member expression as the stored value', async () => {
      const findings = await runRule(
        insecureStorageRule,
        'src/auth/session.ts',
        'await AsyncStorage.setItem("state", response.accessToken);'
      );

      expect(findings).toHaveLength(1);
    });

    it('reports MMKV, which is not encrypted by default', async () => {
      const findings = await runRule(
        insecureStorageRule,
        'src/auth/session.ts',
        'storage.set("sessionToken", token);'
      );

      expect(findings).toHaveLength(1);
    });
  });

  describe('false positives it must not produce', () => {
    it('ignores a key called "keyboardHeight"', async () => {
      const findings = await runRule(
        insecureStorageRule,
        'src/layout.ts',
        'await AsyncStorage.setItem("keyboardHeight", String(height));'
      );

      expect(findings).toEqual([]);
    });

    it('ignores reads, which do not create the exposure', async () => {
      const findings = await runRule(
        insecureStorageRule,
        'src/auth/session.ts',
        'const token = await AsyncStorage.getItem("refreshToken");'
      );

      expect(findings).toEqual([]);
    });

    it('ignores a password field label', async () => {
      const findings = await runRule(
        insecureStorageRule,
        'src/ui/form.ts',
        'await AsyncStorage.setItem("passwordPlaceholder", "Enter password");'
      );

      expect(findings).toEqual([]);
    });
  });
});
