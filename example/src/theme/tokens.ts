/**
 * Design tokens for the example app.
 *
 * Two rules shape this palette, and both come from what the app is showing:
 *
 * **Status colour is semantic, never decorative.** `secure`, `detected`,
 * `unknown`, `unavailable` and `error` are five distinct outcomes in the
 * toolkit's result model, and the UI must not blur them — painting `unknown`
 * the same green as `secure` would overclaim in pixels what the API is careful
 * not to overclaim in types.
 *
 * **Colour is never the only carrier.** Every status is also given a glyph and a
 * word, so the screens stay readable for colour-blind users and in screenshots
 * that lose saturation.
 */

import { Platform } from 'react-native';
import type { SecurityStatus, SignalOutcome } from 'react-native-security-toolkit';

export type ColorScheme = 'light' | 'dark';

export interface Palette {
  /** Page background. */
  readonly background: string;
  /** Cards and grouped rows. */
  readonly surface: string;
  /** A card sitting on a card — filter chips, metadata blocks. */
  readonly surfaceRaised: string;
  /** Hairline dividers and card outlines. */
  readonly border: string;
  /** Outline for a focused or selected control. */
  readonly borderStrong: string;
  readonly text: string;
  readonly textMuted: string;
  readonly textFaint: string;
  /** Interactive accent: buttons, active tab, links. */
  readonly accent: string;
  /** Accent at card-fill strength. */
  readonly accentSoft: string;
  readonly accentText: string;
  /** Status colours, keyed by the toolkit's own `SecurityStatus`. */
  readonly status: Readonly<Record<SecurityStatus, string>>;
  /** Same five colours at fill strength, for pills and tinted icon badges. */
  readonly statusSoft: Readonly<Record<SecurityStatus, string>>;
  readonly risk: Readonly<Record<'minimal' | 'low' | 'medium' | 'high' | 'critical', string>>;
  readonly outcome: Readonly<Record<SignalOutcome, string>>;
  /** Track behind a gauge or bar. */
  readonly track: string;
  /** Shadow colour; kept separate so light mode can soften it. */
  readonly shadow: string;
}

const dark: Palette = {
  background: '#080A0E',
  surface: '#11141B',
  surfaceRaised: '#171B24',
  border: '#222835',
  borderStrong: '#2F3746',
  text: '#ECEFF6',
  textMuted: '#8B94A7',
  textFaint: '#5C6578',
  accent: '#5B8CFF',
  accentSoft: 'rgba(91, 140, 255, 0.16)',
  accentText: '#FFFFFF',
  status: {
    secure: '#2FD37E',
    detected: '#FF5C6C',
    unknown: '#FFB43D',
    unavailable: '#7A8395',
    error: '#FF8A4C',
  },
  statusSoft: {
    secure: 'rgba(47, 211, 126, 0.14)',
    detected: 'rgba(255, 92, 108, 0.15)',
    unknown: 'rgba(255, 180, 61, 0.15)',
    unavailable: 'rgba(122, 131, 149, 0.15)',
    error: 'rgba(255, 138, 76, 0.15)',
  },
  risk: {
    minimal: '#2FD37E',
    low: '#7BD88F',
    medium: '#FFB43D',
    high: '#FF7A45',
    critical: '#FF5C6C',
  },
  outcome: {
    detected: '#FF5C6C',
    indeterminate: '#FFB43D',
    'not-detected': '#2FD37E',
  },
  track: 'rgba(255, 255, 255, 0.08)',
  shadow: '#000000',
};

const light: Palette = {
  background: '#F5F6FA',
  surface: '#FFFFFF',
  surfaceRaised: '#F3F5F9',
  border: '#E3E7EF',
  borderStrong: '#CDD4E0',
  text: '#0D1117',
  textMuted: '#5A6478',
  textFaint: '#8A93A6',
  accent: '#2F5FE0',
  accentSoft: 'rgba(47, 95, 224, 0.10)',
  accentText: '#FFFFFF',
  status: {
    secure: '#0E9F5A',
    detected: '#D62438',
    unknown: '#B06A00',
    unavailable: '#6B7484',
    error: '#C2530A',
  },
  statusSoft: {
    secure: 'rgba(14, 159, 90, 0.10)',
    detected: 'rgba(214, 36, 56, 0.09)',
    unknown: 'rgba(176, 106, 0, 0.10)',
    unavailable: 'rgba(107, 116, 132, 0.10)',
    error: 'rgba(194, 83, 10, 0.10)',
  },
  risk: {
    minimal: '#0E9F5A',
    low: '#3FA76B',
    medium: '#B06A00',
    high: '#D2601A',
    critical: '#D62438',
  },
  outcome: {
    detected: '#D62438',
    indeterminate: '#B06A00',
    'not-detected': '#0E9F5A',
  },
  track: 'rgba(13, 17, 23, 0.07)',
  shadow: '#1B2438',
};

export const PALETTES: Readonly<Record<ColorScheme, Palette>> = Object.freeze({ dark, light });

/** 4pt spacing scale. Every gap and inset in the app comes from here. */
export const space = Object.freeze({
  xxs: 2,
  xs: 4,
  sm: 8,
  md: 12,
  lg: 16,
  xl: 20,
  xxl: 28,
  xxxl: 40,
});

export const radius = Object.freeze({
  sm: 8,
  md: 12,
  lg: 16,
  xl: 22,
  pill: 999,
});

/**
 * Type scale.
 *
 * Deliberately short: five text roles plus a monospace role for identifiers.
 * Signal ids such as `RNSEC-ANDROID-ROOT-005` are data an engineer will compare
 * character by character, so they get a monospace face and never a proportional
 * one.
 */
export const type = Object.freeze({
  display: { fontSize: 34, lineHeight: 38, fontWeight: '700' },
  title: { fontSize: 22, lineHeight: 27, fontWeight: '700' },
  heading: { fontSize: 16, lineHeight: 21, fontWeight: '600' },
  body: { fontSize: 14, lineHeight: 20, fontWeight: '400' },
  bodyStrong: { fontSize: 14, lineHeight: 20, fontWeight: '600' },
  caption: { fontSize: 12, lineHeight: 17, fontWeight: '400' },
  label: { fontSize: 11, lineHeight: 14, fontWeight: '700', letterSpacing: 0.7 },
} as const);

export const monoFamily = Platform.select({ ios: 'Menlo', default: 'monospace' });

export const mono = Object.freeze({
  fontFamily: monoFamily,
  fontSize: 11.5,
  lineHeight: 16,
});

/** Card elevation. Subtle on purpose: the data should carry the hierarchy. */
export function cardShadow(palette: Palette, scheme: ColorScheme) {
  return Platform.select({
    ios: {
      shadowColor: palette.shadow,
      shadowOpacity: scheme === 'dark' ? 0.5 : 0.07,
      shadowRadius: 14,
      shadowOffset: { width: 0, height: 6 },
    },
    android: { elevation: scheme === 'dark' ? 0 : 2 },
    default: {},
  });
}
