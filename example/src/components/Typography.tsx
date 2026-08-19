/**
 * Text primitives.
 *
 * Screens compose these rather than styling `Text` directly, so the type scale
 * and the theme's text colours stay in one place. `Mono` exists because signal
 * identifiers are data an engineer compares character by character.
 */

import type { ReactNode } from 'react';
import { StyleSheet, Text, type StyleProp, type TextStyle } from 'react-native';
import { useTheme } from '../theme/theme';
import { mono, type as scale } from '../theme/tokens';

type Tone = 'default' | 'muted' | 'faint' | 'accent';

interface TextProps {
  readonly children: ReactNode;
  readonly tone?: Tone | undefined;
  /** Overrides the tone entirely — used for status-coloured text. */
  readonly color?: string | undefined;
  readonly style?: StyleProp<TextStyle> | undefined;
  readonly numberOfLines?: number | undefined;
}

function useTone(tone: Tone, color?: string): string {
  const { palette } = useTheme();
  if (color !== undefined) {
    return color;
  }
  switch (tone) {
    case 'muted':
      return palette.textMuted;
    case 'faint':
      return palette.textFaint;
    case 'accent':
      return palette.accent;
    case 'default':
      return palette.text;
  }
}

function make(base: TextStyle) {
  return function Styled({ children, tone = 'default', color, style, numberOfLines }: TextProps) {
    const resolved = useTone(tone, color);
    return (
      <Text style={[base, { color: resolved }, style]} numberOfLines={numberOfLines}>
        {children}
      </Text>
    );
  };
}

export const Display = make(scale.display as TextStyle);
export const Title = make(scale.title as TextStyle);
export const Heading = make(scale.heading as TextStyle);
export const Body = make(scale.body as TextStyle);
export const BodyStrong = make(scale.bodyStrong as TextStyle);
export const Caption = make(scale.caption as TextStyle);

/** Small uppercase kicker used above titles and over grouped rows. */
export const Label = make({ ...(scale.label as TextStyle), textTransform: 'uppercase' });

export const Mono = make(mono as TextStyle);

export const textStyles = StyleSheet.create({
  right: { textAlign: 'right' },
  center: { textAlign: 'center' },
});
