import fs from 'node:fs/promises';
import path from 'node:path';

import { elementsNamed, scanPlist, scanXml } from './analysis/xml.js';

/**
 * Project readiness for the runtime security checks.
 *
 * **This runs no security check.** Root detection, jailbreak detection and the
 * rest execute inside the application on a device; a static analyser cannot
 * perform them, and one that pretended to would be exactly the fabricated
 * capability the brief forbids.
 *
 * What it can establish is whether the project has declared the things those
 * checks depend on. That matters because the failure is silent: a signal whose
 * permission was never declared does not error, it reports `unknown` — which is
 * honest, and easy to miss in a report.
 *
 * It lives in the auditor rather than in the CLI because it is static analysis
 * of a project's own configuration, and because two consumers need it: the CLI
 * and the MCP server.
 */

export interface RuntimeReadiness {
  readonly platform: 'android' | 'ios' | 'project';
  readonly item: string;
  readonly state: 'ready' | 'missing' | 'not-found';
  readonly detail: string;
}

/**
 * Runs every readiness check for a project.
 *
 * Missing items are advice, never a failure: a project may deliberately not use
 * the checks that depend on them.
 */
export async function analyseRuntimeReadiness(root: string): Promise<readonly RuntimeReadiness[]> {
  const checks: RuntimeReadiness[] = [];

  checks.push(await checkPackageInstalled(root));
  checks.push(...(await checkAndroidManifest(root)));
  checks.push(...(await checkInfoPlist(root)));
  checks.push(await checkIntegrityConfigured(root));

  return checks;
}

async function readIfPresent(file: string): Promise<string | undefined> {
  try {
    return await fs.readFile(file, 'utf8');
  } catch {
    return undefined;
  }
}

async function checkPackageInstalled(target: string): Promise<RuntimeReadiness> {
  const manifest = await readIfPresent(path.join(target, 'package.json'));
  if (manifest === undefined) {
    return {
      platform: 'project',
      item: 'react-native-security-toolkit dependency',
      state: 'not-found',
      detail: 'No package.json here, so this does not look like a React Native project root.',
    };
  }

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(manifest) as Record<string, unknown>;
  } catch {
    return {
      platform: 'project',
      item: 'react-native-security-toolkit dependency',
      state: 'not-found',
      detail: 'package.json is not valid JSON.',
    };
  }

  const dependencies = {
    ...((parsed['dependencies'] ?? {}) as Record<string, unknown>),
    ...((parsed['devDependencies'] ?? {}) as Record<string, unknown>),
  };
  const installed = dependencies['react-native-security-toolkit'] !== undefined;

  return {
    platform: 'project',
    item: 'react-native-security-toolkit dependency',
    state: installed ? 'ready' : 'missing',
    detail: installed
      ? 'The runtime package is a dependency of this project.'
      : 'The runtime package is not a dependency here. Static auditing works without it; runtime checks need it.',
  };
}

/** Android permissions and configuration that specific runtime signals depend on. */
async function checkAndroidManifest(target: string): Promise<readonly RuntimeReadiness[]> {
  const candidates = [
    path.join(target, 'android/app/src/main/AndroidManifest.xml'),
    path.join(target, 'app/src/main/AndroidManifest.xml'),
    path.join(target, 'AndroidManifest.xml'),
  ];

  let source: string | undefined;
  for (const candidate of candidates) {
    source = await readIfPresent(candidate);
    if (source !== undefined) {
      break;
    }
  }

  if (source === undefined) {
    return [
      {
        platform: 'android',
        item: 'AndroidManifest.xml',
        state: 'not-found',
        detail: 'No manifest found; skipping the Android checks.',
      },
    ];
  }

  const elements = scanXml(source);
  const permissions = new Set(
    elementsNamed(elements, 'uses-permission')
      .map((element) => element.attributes['android:name'])
      .filter((name): name is string => name !== undefined)
  );

  const application = elementsNamed(elements, 'application')[0];

  return [
    {
      platform: 'android',
      item: 'USE_BIOMETRIC permission',
      state: permissions.has('android.permission.USE_BIOMETRIC') ? 'ready' : 'missing',
      detail: permissions.has('android.permission.USE_BIOMETRIC')
        ? 'BiometricSecurity.getStatus() can query the platform.'
        : 'Without it the platform refuses the query and every biometric signal reports "unknown".',
    },
    {
      platform: 'android',
      item: 'ACCESS_NETWORK_STATE permission',
      state: permissions.has('android.permission.ACCESS_NETWORK_STATE') ? 'ready' : 'missing',
      detail: permissions.has('android.permission.ACCESS_NETWORK_STATE')
        ? 'The VPN transport signal can read network state.'
        : 'Without it the VPN signal in NetworkSecurity.getStatus() reports "unknown".',
    },
    {
      platform: 'android',
      item: 'networkSecurityConfig',
      state:
        application?.attributes['android:networkSecurityConfig'] === undefined
          ? 'missing'
          : 'ready',
      detail:
        application?.attributes['android:networkSecurityConfig'] === undefined
          ? 'No Network Security Config is referenced. Cleartext policy then comes from platform defaults only.'
          : 'A Network Security Config is referenced, so the cleartext policy is explicit.',
    },
  ];
}

/** iOS declarations that specific runtime signals depend on. */
async function checkInfoPlist(target: string): Promise<readonly RuntimeReadiness[]> {
  const candidates = await findPlists(target);

  if (candidates.length === 0) {
    return [
      {
        platform: 'ios',
        item: 'Info.plist',
        state: 'not-found',
        detail: 'No Info.plist found; skipping the iOS checks.',
      },
    ];
  }

  const source = candidates[0] ?? '';
  const entries = scanPlist(source);
  const keys = new Set(entries.map((entry) => entry.keyPath.split('.').pop() ?? ''));

  return [
    {
      platform: 'ios',
      item: 'LSApplicationQueriesSchemes',
      state: keys.has('LSApplicationQueriesSchemes') ? 'ready' : 'missing',
      detail: keys.has('LSApplicationQueriesSchemes')
        ? 'The jailbreak package-manager URL-scheme signal can be evaluated.'
        : 'Without declared schemes, canOpenURL answers false for everything and that signal reports "unknown". ' +
          'Declaring them is visible in App Review, so it is deliberately opt-in.',
    },
    {
      platform: 'ios',
      item: 'NSFaceIDUsageDescription',
      state: keys.has('NSFaceIDUsageDescription') ? 'ready' : 'missing',
      detail: keys.has('NSFaceIDUsageDescription')
        ? 'Face ID can be used for biometric authentication.'
        : 'Without it the system refuses Face ID, and biometric capability reports what is left.',
    },
  ];
}

async function findPlists(target: string): Promise<readonly string[]> {
  const iosDirectory = path.join(target, 'ios');
  const found: string[] = [];

  try {
    const entries = await fs.readdir(iosDirectory, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) {
        continue;
      }
      const source = await readIfPresent(path.join(iosDirectory, entry.name, 'Info.plist'));
      if (source !== undefined) {
        found.push(source);
      }
    }
  } catch {
    // No ios directory: an Android-only or library project.
  }

  return found;
}

/**
 * Whether the project configures the integrity check.
 *
 * A heuristic on purpose, and reported as one: three of the four integrity
 * signals report `indeterminate` until the application says what it expects, and
 * that is the most commonly missed piece of runtime setup.
 */
async function checkIntegrityConfigured(target: string): Promise<RuntimeReadiness> {
  const roots = ['src', 'app', 'lib'];
  for (const root of roots) {
    const found = await searchForIntegrityConfig(path.join(target, root), 0);
    if (found) {
      return {
        platform: 'project',
        item: 'IntegrityCheck configuration',
        state: 'ready',
        detail: 'SecurityToolkit.configure appears to supply integrity options.',
      };
    }
  }

  return {
    platform: 'project',
    item: 'IntegrityCheck configuration',
    state: 'missing',
    detail:
      'No SecurityToolkit.configure({ integrity: ... }) found. Without expected signing certificates, ' +
      'installers and package name, those signals report "indeterminate" rather than passing.',
  };
}

async function searchForIntegrityConfig(directory: string, depth: number): Promise<boolean> {
  if (depth > 4) {
    return false;
  }

  let entries;
  try {
    entries = await fs.readdir(directory, { withFileTypes: true });
  } catch {
    return false;
  }

  for (const entry of entries) {
    if (entry.isSymbolicLink() || entry.name === 'node_modules') {
      continue;
    }
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      if (await searchForIntegrityConfig(full, depth + 1)) {
        return true;
      }
      continue;
    }
    if (!/\.(?:ts|tsx|js|jsx)$/.test(entry.name)) {
      continue;
    }
    const source = await readIfPresent(full);
    if (
      source !== undefined &&
      /SecurityToolkit\.configure\s*\(/.test(source) &&
      /integrity/.test(source)
    ) {
      return true;
    }
  }

  return false;
}
