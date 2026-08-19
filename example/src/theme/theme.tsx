/**
 * Theme plumbing.
 *
 * The app follows the system colour scheme rather than offering its own toggle:
 * a security console that ignores the OS setting looks like a web page in a
 * WebView, and the screenshots in the README should match the reader's device.
 */

import { createContext, useContext, useMemo, type ReactNode } from 'react';
import { useColorScheme } from 'react-native';
import { PALETTES, type ColorScheme, type Palette } from './tokens';

export interface Theme {
  readonly scheme: ColorScheme;
  readonly palette: Palette;
  readonly isDark: boolean;
}

const ThemeContext = createContext<Theme>({
  scheme: 'dark',
  palette: PALETTES.dark,
  isDark: true,
});

export function ThemeProvider({ children }: { readonly children: ReactNode }) {
  const scheme: ColorScheme = useColorScheme() === 'light' ? 'light' : 'dark';
  const value = useMemo<Theme>(
    () => ({ scheme, palette: PALETTES[scheme], isDark: scheme === 'dark' }),
    [scheme]
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): Theme {
  return useContext(ThemeContext);
}
