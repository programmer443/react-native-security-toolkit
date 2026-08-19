import { appTransportSecurityRule } from '../ios/appTransportSecurity.js';
import {
  exportedComponentRule,
  manifestConfigurationRule,
} from '../android/manifestConfiguration.js';
import { runRule } from './helpers/runRule.js';

const MANIFEST_PATH = 'android/app/src/main/AndroidManifest.xml';
const PLIST_PATH = 'ios/App/Info.plist';

function plist(body: string): string {
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    '<plist version="1.0">',
    '<dict>',
    body,
    '</dict>',
    '</plist>',
  ].join('\n');
}

describe('RNSEC-ANDROID-MANIFEST-001 insecure manifest configuration', () => {
  describe('true positives', () => {
    it('reports a debuggable application', async () => {
      const findings = await runRule(
        manifestConfigurationRule,
        MANIFEST_PATH,
        '<manifest><application android:debuggable="true" /></manifest>'
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.title).toContain('debuggable');
      // Gradle can override it per build type, so the manifest alone is not proof.
      expect(findings[0]?.confidence).toBe('medium');
    });

    it('reports backups and cleartext traffic', async () => {
      const findings = await runRule(
        manifestConfigurationRule,
        MANIFEST_PATH,
        '<manifest><application android:allowBackup="true" android:usesCleartextTraffic="true" /></manifest>'
      );

      expect(findings).toHaveLength(2);
      expect(findings.map((finding) => finding.title).join(' ')).toContain('backups');
    });
  });

  describe('true negatives', () => {
    it('says nothing about a hardened manifest', async () => {
      const findings = await runRule(
        manifestConfigurationRule,
        MANIFEST_PATH,
        '<manifest><application android:allowBackup="false" android:usesCleartextTraffic="false" /></manifest>'
      );

      expect(findings).toEqual([]);
    });
  });

  describe('edge cases', () => {
    it('reads attributes across several lines and single quotes', async () => {
      const findings = await runRule(
        manifestConfigurationRule,
        MANIFEST_PATH,
        [
          '<manifest>',
          '  <application',
          "    android:label='App'",
          '    android:allowBackup="true">',
          '  </application>',
          '</manifest>',
        ].join('\n')
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.location.line).toBe(2);
    });
  });

  describe('false positives it must not produce', () => {
    it('ignores the same attribute on a component rather than the application', async () => {
      const findings = await runRule(
        manifestConfigurationRule,
        MANIFEST_PATH,
        '<manifest><application><activity android:allowBackup="true" /></application></manifest>'
      );

      expect(findings).toEqual([]);
    });
  });
});

describe('RNSEC-ANDROID-MANIFEST-002 exported component without a permission', () => {
  describe('true positives', () => {
    it('reports an exported service with no permission', async () => {
      const findings = await runRule(
        exportedComponentRule,
        MANIFEST_PATH,
        '<manifest><application><service android:name=".SyncService" android:exported="true" /></application></manifest>'
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.title).toContain('SyncService');
    });

    it('treats an exported provider as more serious than an exported activity', async () => {
      const findings = await runRule(
        exportedComponentRule,
        MANIFEST_PATH,
        '<manifest><application><provider android:name=".DataProvider" android:exported="true" /></application></manifest>'
      );

      expect(findings[0]?.severity).toBe('high');
    });
  });

  describe('true negatives', () => {
    it('says nothing when a permission is required', async () => {
      const findings = await runRule(
        exportedComponentRule,
        MANIFEST_PATH,
        '<manifest><application><service android:name=".SyncService" android:exported="true" android:permission="com.app.SYNC" /></application></manifest>'
      );

      expect(findings).toEqual([]);
    });

    it('says nothing about components that are not exported', async () => {
      const findings = await runRule(
        exportedComponentRule,
        MANIFEST_PATH,
        '<manifest><application><activity android:name=".Secret" android:exported="false" /></application></manifest>'
      );

      expect(findings).toEqual([]);
    });
  });

  describe('edge cases', () => {
    it('accepts read and write permissions on a provider', async () => {
      const findings = await runRule(
        exportedComponentRule,
        MANIFEST_PATH,
        '<manifest><provider android:name=".P" android:exported="true" android:readPermission="com.app.READ" /></manifest>'
      );

      expect(findings).toEqual([]);
    });
  });

  describe('false positives it must not produce', () => {
    it('ignores the launcher activity, which must be exported', async () => {
      // §36 warns against blindly flagging every exported component, and the
      // launcher is the clearest example of why.
      const findings = await runRule(
        exportedComponentRule,
        MANIFEST_PATH,
        [
          '<manifest><application>',
          '  <activity android:name=".MainActivity" android:exported="true">',
          '    <intent-filter>',
          '      <action android:name="android.intent.action.MAIN" />',
          '      <category android:name="android.intent.category.LAUNCHER" />',
          '    </intent-filter>',
          '  </activity>',
          '</application></manifest>',
        ].join('\n')
      );

      expect(findings).toEqual([]);
    });
  });
});

describe('RNSEC-IOS-PLIST-001 App Transport Security weakened', () => {
  describe('true positives', () => {
    it('reports ATS being disabled application-wide', async () => {
      const findings = await runRule(
        appTransportSecurityRule,
        PLIST_PATH,
        plist(
          '  <key>NSAppTransportSecurity</key>\n  <dict>\n    <key>NSAllowsArbitraryLoads</key>\n    <true/>\n  </dict>'
        )
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.severity).toBe('high');
    });

    it('reports a per-domain cleartext exception at lower severity', async () => {
      // The gradation matters: reporting both at the same severity pushes people
      // towards the blunt fix.
      const findings = await runRule(
        appTransportSecurityRule,
        PLIST_PATH,
        plist(
          [
            '  <key>NSAppTransportSecurity</key>',
            '  <dict>',
            '    <key>NSExceptionDomains</key>',
            '    <dict>',
            '      <key>legacy.partner.com</key>',
            '      <dict>',
            '        <key>NSExceptionAllowsInsecureHTTPLoads</key>',
            '        <true/>',
            '      </dict>',
            '    </dict>',
            '  </dict>',
          ].join('\n')
        )
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.severity).toBe('medium');
      expect(findings[0]?.title).toContain('legacy.partner.com');
    });

    it('reports a TLS minimum below 1.2', async () => {
      const findings = await runRule(
        appTransportSecurityRule,
        PLIST_PATH,
        plist(
          [
            '  <key>NSExceptionDomains</key>',
            '  <dict>',
            '    <key>api.partner.com</key>',
            '    <dict>',
            '      <key>NSExceptionMinimumTLSVersion</key>',
            '      <string>TLSv1.0</string>',
            '    </dict>',
            '  </dict>',
          ].join('\n')
        )
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.title).toContain('TLSv1.0');
    });
  });

  describe('true negatives', () => {
    it('says nothing about a plist with ATS left alone', async () => {
      const findings = await runRule(
        appTransportSecurityRule,
        PLIST_PATH,
        plist('  <key>CFBundleName</key>\n  <string>Example</string>')
      );

      expect(findings).toEqual([]);
    });

    it('says nothing when the flag is explicitly false', async () => {
      const findings = await runRule(
        appTransportSecurityRule,
        PLIST_PATH,
        plist('  <key>NSAllowsArbitraryLoads</key>\n  <false/>')
      );

      expect(findings).toEqual([]);
    });
  });

  describe('edge cases', () => {
    it('reports arbitrary loads in web content separately from the global flag', async () => {
      const findings = await runRule(
        appTransportSecurityRule,
        PLIST_PATH,
        plist('  <key>NSAllowsArbitraryLoadsInWebContent</key>\n  <true/>')
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.severity).toBe('medium');
    });
  });

  describe('false positives it must not produce', () => {
    it('ignores the localhost exception React Native adds for Metro', async () => {
      const findings = await runRule(
        appTransportSecurityRule,
        PLIST_PATH,
        plist(
          [
            '  <key>NSExceptionDomains</key>',
            '  <dict>',
            '    <key>localhost</key>',
            '    <dict>',
            '      <key>NSExceptionAllowsInsecureHTTPLoads</key>',
            '      <true/>',
            '    </dict>',
            '  </dict>',
          ].join('\n')
        )
      );

      expect(findings).toEqual([]);
    });
  });
});
