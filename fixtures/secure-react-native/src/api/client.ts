import * as SecureStore from 'expo-secure-store';

export const BASE_URL = 'https://api.secure-fixture.test/v1';

// Supplied at runtime, never built into the binary.
const apiKey = process.env.API_KEY;

export async function signIn(username: string, password: string): Promise<void> {
  const response = await fetch(`${BASE_URL}/login`, {
    method: 'POST',
    headers: { 'x-api-key': apiKey ?? '' },
    body: JSON.stringify({ username, password }),
  });
  const { refreshToken } = await response.json();

  console.log('signed in');
  await SecureStore.setItemAsync('refreshToken', refreshToken);
}

export function makeSessionToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export const theme = { placeholder: 'Enter your password', tokenCount: 4096 };
