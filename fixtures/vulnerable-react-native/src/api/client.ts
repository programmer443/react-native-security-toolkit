// Deliberately insecure fixture. Every line here exists to make a rule fire.
import AsyncStorage from '@react-native-async-storage/async-storage';

export const BASE_URL = 'http://api.insecure-fixture.test/v1';

// Syntactically valid, functionally useless: this is not a live credential.
const stripeSecretKey = 'sk_test_EXAMPLEONLY000000';

export async function signIn(username: string, password: string): Promise<void> {
  const response = await fetch(`${BASE_URL}/login`, {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
  const { accessToken, refreshToken } = await response.json();

  console.log('signed in with token', accessToken);
  await AsyncStorage.setItem('refreshToken', refreshToken);
}

export function makeSessionToken(): string {
  return Math.random().toString(36).slice(2);
}

export const stripe = { key: stripeSecretKey };
