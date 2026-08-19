/**
 * Buttons, segmented controls and toggle rows.
 *
 * Pressed states are explicit (`pressed` opacity plus a tint) rather than left to
 * the platform default, because several of these controls sit on tinted cards
 * where the default highlight is invisible.
 */

import type { ReactNode } from 'react';
import { Pressable, StyleSheet, Switch, View, type StyleProp, type ViewStyle } from 'react-native';
import { useTheme } from '../theme/theme';
import { radius, space } from '../theme/tokens';
import { Body, BodyStrong, Caption, Label } from './Typography';
import type { IconComponent } from '../icons';

export function PrimaryButton({
  label,
  onPress,
  icon: Glyph,
  disabled = false,
  busy = false,
  tone,
}: {
  readonly label: string;
  readonly onPress: () => void;
  readonly icon?: IconComponent | undefined;
  readonly disabled?: boolean | undefined;
  readonly busy?: boolean | undefined;
  /** Overrides the accent, so a destructive or status-coloured action can differ. */
  readonly tone?: string | undefined;
}) {
  const { palette } = useTheme();
  const background = tone ?? palette.accent;
  const inactive = disabled || busy;

  return (
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ disabled: inactive }}
      disabled={inactive}
      onPress={onPress}
      style={({ pressed }) => [
        styles.primary,
        { backgroundColor: background, opacity: inactive ? 0.5 : pressed ? 0.85 : 1 },
      ]}
    >
      {Glyph === undefined ? null : <Glyph size={16} color={palette.accentText} strokeWidth={2} />}
      <BodyStrong color={palette.accentText}>{busy ? 'Working…' : label}</BodyStrong>
    </Pressable>
  );
}

export function GhostButton({
  label,
  onPress,
  icon: Glyph,
  tone,
}: {
  readonly label: string;
  readonly onPress: () => void;
  readonly icon?: IconComponent | undefined;
  readonly tone?: string | undefined;
}) {
  const { palette } = useTheme();
  const color = tone ?? palette.accent;
  return (
    <Pressable
      accessibilityRole="button"
      onPress={onPress}
      style={({ pressed }) => [
        styles.ghost,
        { borderColor: palette.border, opacity: pressed ? 0.6 : 1 },
      ]}
    >
      {Glyph === undefined ? null : <Glyph size={14} color={color} strokeWidth={2} />}
      <Caption color={color}>{label}</Caption>
    </Pressable>
  );
}

export function IconButton({
  icon: Glyph,
  onPress,
  label,
  tone,
  busy = false,
}: {
  readonly icon: IconComponent;
  readonly onPress: () => void;
  /** Accessibility label; icon-only controls need one. */
  readonly label: string;
  readonly tone?: string | undefined;
  readonly busy?: boolean | undefined;
}) {
  const { palette } = useTheme();
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={label}
      onPress={onPress}
      disabled={busy}
      hitSlop={8}
      style={({ pressed }) => [
        styles.iconButton,
        {
          backgroundColor: palette.surfaceRaised,
          borderColor: palette.border,
          opacity: busy ? 0.45 : pressed ? 0.6 : 1,
        },
      ]}
    >
      <Glyph size={17} color={tone ?? palette.text} strokeWidth={2} />
    </Pressable>
  );
}

export interface SegmentOption<T extends string> {
  readonly value: T;
  readonly label: string;
  /** Optional count shown after the label, for filter rows. */
  readonly count?: number | undefined;
}

export function Segmented<T extends string>({
  options,
  value,
  onChange,
  style,
}: {
  readonly options: readonly SegmentOption<T>[];
  readonly value: T;
  readonly onChange: (next: T) => void;
  readonly style?: StyleProp<ViewStyle> | undefined;
}) {
  const { palette } = useTheme();
  return (
    <View
      style={[
        styles.segmented,
        { backgroundColor: palette.surfaceRaised, borderColor: palette.border },
        style,
      ]}
    >
      {options.map((option) => {
        const active = option.value === value;
        return (
          <Pressable
            key={option.value}
            accessibilityRole="button"
            accessibilityState={{ selected: active }}
            onPress={() => onChange(option.value)}
            style={({ pressed }) => [
              styles.segment,
              active
                ? { backgroundColor: palette.surface, borderColor: palette.borderStrong }
                : null,
              { opacity: pressed && !active ? 0.6 : 1 },
            ]}
          >
            <Caption
              tone={active ? 'default' : 'muted'}
              style={active ? styles.segmentActiveText : undefined}
            >
              {option.count === undefined ? option.label : `${option.label} ${option.count}`}
            </Caption>
          </Pressable>
        );
      })}
    </View>
  );
}

/** Labelled switch with a rationale line. Policy screens live on these. */
export function ToggleRow({
  title,
  description,
  value,
  onChange,
  disabled = false,
}: {
  readonly title: string;
  readonly description: string;
  readonly value: boolean;
  readonly onChange: (next: boolean) => void;
  readonly disabled?: boolean | undefined;
}) {
  const { palette } = useTheme();
  return (
    <View style={[styles.toggleRow, disabled ? styles.toggleDisabled : null]}>
      <View style={styles.toggleText}>
        <BodyStrong>{title}</BodyStrong>
        <Caption tone="muted">{description}</Caption>
      </View>
      <Switch
        value={value}
        onValueChange={onChange}
        disabled={disabled}
        trackColor={{ false: palette.track, true: palette.accent }}
        thumbColor={palette.surface}
        ios_backgroundColor={palette.track}
      />
    </View>
  );
}

/** Pressable row used by lists that navigate. */
export function PressableRow({
  onPress,
  children,
  style,
}: {
  readonly onPress: () => void;
  readonly children: ReactNode;
  readonly style?: StyleProp<ViewStyle> | undefined;
}) {
  return (
    <Pressable
      accessibilityRole="button"
      onPress={onPress}
      style={({ pressed }) => [style, { opacity: pressed ? 0.55 : 1 }]}
    >
      {children}
    </Pressable>
  );
}

/** Inline note with an icon: caveats, platform differences, disclaimers. */
export function Note({
  icon: Glyph,
  children,
  tone,
}: {
  readonly icon: IconComponent;
  readonly children: string;
  readonly tone?: string | undefined;
}) {
  const { palette } = useTheme();
  const color = tone ?? palette.textFaint;
  return (
    <View style={styles.note}>
      <View style={styles.noteIcon}>
        <Glyph size={14} color={color} strokeWidth={1.9} />
      </View>
      <Caption tone="muted" style={styles.noteText}>
        {children}
      </Caption>
    </View>
  );
}

/** Uppercase caption used as a mini table header inside a card. */
export function MiniHeader({ children }: { readonly children: string }) {
  return <Label tone="faint">{children}</Label>;
}

/** Plain body row used for a paragraph inside a card. */
export function Paragraph({ children }: { readonly children: string }) {
  return <Body tone="muted">{children}</Body>;
}

const styles = StyleSheet.create({
  primary: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: space.sm,
    paddingVertical: 13,
    paddingHorizontal: space.lg,
    borderRadius: radius.md,
  },
  ghost: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: space.xs,
    paddingVertical: 7,
    paddingHorizontal: space.md,
    borderRadius: radius.pill,
    borderWidth: StyleSheet.hairlineWidth,
    alignSelf: 'flex-start',
  },
  iconButton: {
    width: 36,
    height: 36,
    borderRadius: radius.md,
    borderWidth: StyleSheet.hairlineWidth,
    alignItems: 'center',
    justifyContent: 'center',
  },
  segmented: {
    flexDirection: 'row',
    padding: 3,
    borderRadius: radius.md,
    borderWidth: StyleSheet.hairlineWidth,
    gap: 3,
  },
  segment: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: 7,
    paddingHorizontal: 4,
    borderRadius: radius.sm,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: 'transparent',
  },
  segmentActiveText: {
    fontWeight: '600',
  },
  toggleRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: space.md,
  },
  toggleDisabled: {
    opacity: 0.45,
  },
  toggleText: {
    flex: 1,
    gap: 2,
  },
  note: {
    flexDirection: 'row',
    gap: space.sm,
  },
  noteIcon: {
    paddingTop: 1.5,
  },
  noteText: {
    flex: 1,
  },
});
