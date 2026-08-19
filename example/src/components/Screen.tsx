/**
 * Screen scaffold: fixed header, scrolling body, pull-to-refresh.
 *
 * The header stays put while the body scrolls. On a screen whose entire purpose
 * is a verdict, a title that scrolls away takes the context with it — and the
 * refresh action needs to be reachable without scrolling back up.
 */

import type { ReactNode } from 'react';
import { RefreshControl, ScrollView, StyleSheet, View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTheme } from '../theme/theme';
import { space } from '../theme/tokens';
import { Caption, Label, Title } from './Typography';
import { IconButton } from './Controls';
import { ArrowLeftIcon } from '../icons';

export const TAB_BAR_HEIGHT = 60;

export function Screen({
  kicker,
  title,
  subtitle,
  onBack,
  action,
  refreshing,
  onRefresh,
  withTabBar = true,
  children,
}: {
  readonly kicker?: string | undefined;
  readonly title: string;
  readonly subtitle?: string | undefined;
  readonly onBack?: () => void | undefined;
  readonly action?: ReactNode | undefined;
  readonly refreshing?: boolean | undefined;
  readonly onRefresh?: () => void | undefined;
  readonly withTabBar?: boolean | undefined;
  readonly children: ReactNode;
}) {
  const { palette } = useTheme();
  const insets = useSafeAreaInsets();

  return (
    <View style={[styles.root, { backgroundColor: palette.background }]}>
      <View
        style={[
          styles.header,
          { paddingTop: insets.top + space.sm, borderBottomColor: palette.border },
        ]}
      >
        {onBack === undefined ? null : (
          <View style={styles.back}>
            <IconButton icon={ArrowLeftIcon} onPress={onBack} label="Back" />
          </View>
        )}
        <View style={styles.headerText}>
          {kicker === undefined ? null : <Label tone="faint">{kicker}</Label>}
          <Title numberOfLines={1}>{title}</Title>
          {subtitle === undefined ? null : (
            <Caption tone="muted" numberOfLines={2}>
              {subtitle}
            </Caption>
          )}
        </View>
        {action === undefined ? null : <View style={styles.action}>{action}</View>}
      </View>

      <ScrollView
        style={styles.body}
        contentContainerStyle={[
          styles.content,
          {
            paddingBottom: (withTabBar ? TAB_BAR_HEIGHT : 0) + insets.bottom + space.xxl,
          },
        ]}
        showsVerticalScrollIndicator={false}
        refreshControl={
          onRefresh === undefined ? undefined : (
            <RefreshControl
              refreshing={refreshing ?? false}
              onRefresh={onRefresh}
              tintColor={palette.textMuted}
              colors={[palette.accent]}
              progressBackgroundColor={palette.surface}
            />
          )
        }
      >
        {children}
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  root: {
    flex: 1,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'flex-end',
    gap: space.md,
    paddingHorizontal: space.lg,
    paddingBottom: space.md,
    borderBottomWidth: StyleSheet.hairlineWidth,
  },
  back: {
    paddingBottom: 2,
  },
  headerText: {
    flex: 1,
    gap: 2,
  },
  action: {
    paddingBottom: 2,
  },
  body: {
    flex: 1,
  },
  content: {
    paddingHorizontal: space.lg,
    paddingTop: space.lg,
  },
});
