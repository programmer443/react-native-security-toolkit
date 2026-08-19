import { Linking } from 'react-native';

const ALLOWED_HOSTS = new Set(['app.secure-fixture.test']);

export async function handleInitialLink(): Promise<void> {
  const url = await Linking.getInitialURL();
  if (url === null) {
    return;
  }

  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' || !ALLOWED_HOSTS.has(parsed.hostname)) {
    return;
  }
  await Linking.openURL('https://app.secure-fixture.test/home');
}

export function runPlugin(name: string, plugins: Record<string, () => unknown>): unknown {
  return plugins[name]?.();
}
