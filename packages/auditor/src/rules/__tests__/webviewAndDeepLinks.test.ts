import { unsafeWebViewRule } from '../webview/unsafeWebView.js';
import { unvalidatedDeepLinkRule } from '../deeplinks/unvalidatedDeepLink.js';
import { runRule } from './helpers/runRule.js';

describe('RNSEC-WEBVIEW-001 unsafe WebView configuration', () => {
  describe('true positives', () => {
    it('reports a wildcard origin whitelist', async () => {
      const findings = await runRule(
        unsafeWebViewRule,
        'src/screens/Browser.tsx',
        'export const Screen = () => <WebView originWhitelist={["*"]} source={{ uri }} />;'
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.title).toContain('any origin');
    });

    it('reports file access with JavaScript enabled at high severity', async () => {
      const findings = await runRule(
        unsafeWebViewRule,
        'src/screens/Browser.tsx',
        'const S = () => <WebView javaScriptEnabled allowFileAccess source={{ uri }} />;'
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.severity).toBe('high');
    });

    it('reports addJavascriptInterface on Android', async () => {
      const findings = await runRule(
        unsafeWebViewRule,
        'android/app/src/main/java/com/app/Browser.kt',
        'webView.addJavascriptInterface(NativeBridge(), "Android")'
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.title).toContain('Native object exposed');
    });

    it('reports mixed content being allowed', async () => {
      const findings = await runRule(
        unsafeWebViewRule,
        'src/screens/Browser.tsx',
        'const S = () => <WebView mixedContentMode="always" source={{ uri }} />;'
      );

      expect(findings).toHaveLength(1);
    });
  });

  describe('true negatives', () => {
    it('says nothing about a restricted WebView', async () => {
      const findings = await runRule(
        unsafeWebViewRule,
        'src/screens/Browser.tsx',
        'const S = () => <WebView originWhitelist={["https://app.example.com"]} source={{ uri }} />;'
      );

      expect(findings).toEqual([]);
    });

    it('says nothing about a WebView with defaults', async () => {
      const findings = await runRule(
        unsafeWebViewRule,
        'src/screens/Browser.tsx',
        'const S = () => <WebView source={{ uri: "https://app.example.com" }} />;'
      );

      expect(findings).toEqual([]);
    });
  });

  describe('edge cases', () => {
    it('treats a bare boolean attribute as true', async () => {
      // `<WebView allowFileAccess />` is `allowFileAccess={true}`.
      const findings = await runRule(
        unsafeWebViewRule,
        'src/screens/Browser.tsx',
        'const S = () => <WebView allowUniversalAccessFromFileURLs source={{ uri }} />;'
      );

      expect(findings).toHaveLength(1);
    });

    it('recognises a namespaced element name', async () => {
      const findings = await runRule(
        unsafeWebViewRule,
        'src/screens/Browser.tsx',
        'const S = () => <RN.WebView originWhitelist={["*"]} />;'
      );

      expect(findings).toHaveLength(1);
    });
  });

  describe('false positives it must not produce', () => {
    it('ignores an explicit false', async () => {
      const findings = await runRule(
        unsafeWebViewRule,
        'src/screens/Browser.tsx',
        'const S = () => <WebView allowFileAccess={false} mixedContentMode="never" />;'
      );

      expect(findings).toEqual([]);
    });

    it('ignores components that merely end in a similar name', async () => {
      const findings = await runRule(
        unsafeWebViewRule,
        'src/screens/Browser.tsx',
        'const S = () => <PreviewCard allowFileAccess />;'
      );

      expect(findings).toEqual([]);
    });
  });
});

describe('RNSEC-DEEPLINK-001 deep link handled without validation', () => {
  describe('true positives', () => {
    it('reports a URL from a link passed straight to openURL', async () => {
      const findings = await runRule(
        unvalidatedDeepLinkRule,
        'src/navigation/deepLinks.ts',
        [
          'const url = await Linking.getInitialURL();',
          'const target = new URL(url).searchParams.get("next");',
          'await Linking.openURL(target);',
        ].join('\n')
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.confidence).toBe('low');
    });

    it('reports a web intent filter without domain verification', async () => {
      const findings = await runRule(
        unvalidatedDeepLinkRule,
        'android/app/src/main/AndroidManifest.xml',
        [
          '<activity android:name=".MainActivity">',
          '  <intent-filter>',
          '    <action android:name="android.intent.action.VIEW" />',
          '    <data android:scheme="https" android:host="app.example.com" />',
          '  </intent-filter>',
          '</activity>',
        ].join('\n')
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.title).toContain('domain verification');
    });
  });

  describe('true negatives', () => {
    it('says nothing when autoVerify is set', async () => {
      const findings = await runRule(
        unvalidatedDeepLinkRule,
        'android/app/src/main/AndroidManifest.xml',
        [
          '<activity android:name=".MainActivity">',
          '  <intent-filter android:autoVerify="true">',
          '    <data android:scheme="https" android:host="app.example.com" />',
          '  </intent-filter>',
          '</activity>',
        ].join('\n')
      );

      expect(findings).toEqual([]);
    });

    it('says nothing about a file that never reads a link', async () => {
      const findings = await runRule(
        unvalidatedDeepLinkRule,
        'src/support.ts',
        'await Linking.openURL(supportUrl);'
      );

      expect(findings).toEqual([]);
    });
  });

  describe('edge cases', () => {
    it('ignores a custom-scheme filter, which cannot be domain-verified', async () => {
      const findings = await runRule(
        unvalidatedDeepLinkRule,
        'android/app/src/main/AndroidManifest.xml',
        [
          '<intent-filter>',
          '  <data android:scheme="myapp" android:host="callback" />',
          '</intent-filter>',
        ].join('\n')
      );

      expect(findings).toEqual([]);
    });
  });

  describe('false positives it must not produce', () => {
    it('ignores a hardcoded destination even in a deep-link handler', async () => {
      const findings = await runRule(
        unvalidatedDeepLinkRule,
        'src/navigation/deepLinks.ts',
        [
          'const url = await Linking.getInitialURL();',
          'if (!url) { await Linking.openURL("https://app.example.com/home"); }',
        ].join('\n')
      );

      expect(findings).toEqual([]);
    });
  });
});
