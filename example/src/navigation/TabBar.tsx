/**
 * Bottom tab bar.
 *
 * Hand-rolled rather than pulled in with a navigation library: the example has
 * five flat destinations and one push, and a reader installing this package
 * should not have to reason about four extra native dependencies to follow the
 * demo. The trade is real — no deep links, no state restoration — and for an
 * example that is the right side of it.
 */

import { Pressable, StyleSheet, View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTheme } from '../theme/theme';
import { radius, space } from '../theme/tokens';
import { Caption } from '../components/Typography';
import { TAB_BAR_HEIGHT } from '../components/Screen';
import {
  CpuIcon,
  GaugeIcon,
  LayersIcon,
  PulseIcon,
  SlidersIcon,
  type IconComponent,
} from '../icons';

export type TabName = 'overview' | 'checks' | 'signals' | 'policy' | 'engine';

interface TabDefinition {
  readonly name: TabName;
  readonly label: string;
  readonly icon: IconComponent;
}

export const TABS: readonly TabDefinition[] = Object.freeze([
  { name: 'overview', label: 'Posture', icon: GaugeIcon },
  { name: 'checks', label: 'Checks', icon: LayersIcon },
  { name: 'signals', label: 'Signals', icon: PulseIcon },
  { name: 'policy', label: 'Policy', icon: SlidersIcon },
  { name: 'engine', label: 'Engine', icon: CpuIcon },
]);

export function TabBar({
  active,
  onSelect,
}: {
  readonly active: TabName;
  readonly onSelect: (tab: TabName) => void;
}) {
  const { palette } = useTheme();
  const insets = useSafeAreaInsets();

  return (
    <View
      style={[
        styles.bar,
        {
          height: TAB_BAR_HEIGHT + insets.bottom,
          paddingBottom: insets.bottom,
          backgroundColor: palette.surface,
          borderTopColor: palette.border,
        },
      ]}
    >
      {TABS.map((tab) => {
        const selected = tab.name === active;
        const color = selected ? palette.accent : palette.textFaint;
        const Glyph = tab.icon;
        return (
          <Pressable
            key={tab.name}
            accessibilityRole="tab"
            accessibilityState={{ selected }}
            accessibilityLabel={tab.label}
            onPress={() => onSelect(tab.name)}
            style={({ pressed }) => [styles.tab, { opacity: pressed && !selected ? 0.6 : 1 }]}
          >
            <View
              style={[styles.iconWrap, selected ? { backgroundColor: palette.accentSoft } : null]}
            >
              <Glyph size={19} color={color} strokeWidth={selected ? 2.1 : 1.7} />
            </View>
            <Caption color={color} style={selected ? styles.labelActive : undefined}>
              {tab.label}
            </Caption>
          </Pressable>
        );
      })}
    </View>
  );
}

const styles = StyleSheet.create({
  bar: {
    position: 'absolute',
    left: 0,
    right: 0,
    bottom: 0,
    flexDirection: 'row',
    alignItems: 'flex-start',
    paddingTop: space.sm,
    borderTopWidth: StyleSheet.hairlineWidth,
  },
  tab: {
    flex: 1,
    alignItems: 'center',
    gap: 2,
  },
  iconWrap: {
    paddingHorizontal: space.md,
    paddingVertical: 3,
    borderRadius: radius.pill,
  },
  labelActive: {
    fontWeight: '600',
  },
});
