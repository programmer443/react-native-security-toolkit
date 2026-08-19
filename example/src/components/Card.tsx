/**
 * Card, dividers and key/value rows — the surfaces every screen is built from.
 */

import type { ReactNode } from 'react';
import { StyleSheet, View, type StyleProp, type ViewStyle } from 'react-native';
import { useTheme } from '../theme/theme';
import { cardShadow, radius, space } from '../theme/tokens';
import { Body, BodyStrong, Caption, Label, textStyles } from './Typography';

export function Card({
  children,
  style,
  padded = true,
  tint,
  accent,
}: {
  readonly children: ReactNode;
  readonly style?: StyleProp<ViewStyle> | undefined;
  readonly padded?: boolean | undefined;
  /** Background override, for status-tinted cards. */
  readonly tint?: string | undefined;
  /** Left edge colour, used to mark a card as belonging to a status. */
  readonly accent?: string | undefined;
}) {
  const { palette, scheme } = useTheme();
  return (
    <View
      style={[
        styles.card,
        cardShadow(palette, scheme),
        {
          backgroundColor: tint ?? palette.surface,
          borderColor: palette.border,
        },
        accent === undefined ? null : styles.accentEdge,
        accent === undefined ? null : { borderLeftColor: accent },
        padded ? styles.padded : null,
        style,
      ]}
    >
      {children}
    </View>
  );
}

export function Divider() {
  const { palette } = useTheme();
  return <View style={[styles.divider, { backgroundColor: palette.border }]} />;
}

/**
 * A labelled value.
 *
 * `mono` is used for identifiers and versions; everything else reads better in
 * the proportional face.
 */
export function KeyValue({
  label,
  value,
  color,
  wrap = false,
}: {
  readonly label: string;
  readonly value: string;
  readonly color?: string | undefined;
  readonly wrap?: boolean | undefined;
}) {
  return (
    <View style={wrap ? styles.rowWrap : styles.row}>
      <Body tone="muted" style={styles.rowLabel}>
        {label}
      </Body>
      <BodyStrong color={color} style={[styles.rowValue, wrap ? null : textStyles.right]}>
        {value}
      </BodyStrong>
    </View>
  );
}

/** Section heading with an optional trailing hint, used between cards. */
export function SectionHeader({
  title,
  hint,
  style,
}: {
  readonly title: string;
  readonly hint?: string | undefined;
  readonly style?: StyleProp<ViewStyle> | undefined;
}) {
  return (
    <View style={[styles.section, style]}>
      <Label tone="faint">{title}</Label>
      {hint === undefined ? null : (
        <Caption tone="faint" style={styles.sectionHint}>
          {hint}
        </Caption>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    borderRadius: radius.lg,
    borderWidth: StyleSheet.hairlineWidth,
    overflow: 'hidden',
  },
  accentEdge: {
    borderLeftWidth: 3,
  },
  padded: {
    padding: space.lg,
    gap: space.md,
  },
  divider: {
    height: StyleSheet.hairlineWidth,
    marginVertical: space.xs,
  },
  row: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
    gap: space.lg,
  },
  rowWrap: {
    gap: space.xxs,
  },
  rowLabel: {
    flexShrink: 0,
  },
  rowValue: {
    flexShrink: 1,
  },
  section: {
    marginTop: space.xl,
    marginBottom: space.sm,
    gap: space.xxs,
  },
  sectionHint: {
    lineHeight: 16,
  },
});
