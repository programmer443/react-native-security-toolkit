/**
 * Five tabs and one push.
 *
 * The detail screen is an overlay that slides in over the tab bar rather than a
 * sixth tab, because it is always about a specific check you arrived at from
 * somewhere — the posture grid or the checks list — and the way back should be
 * the way you came. Android's hardware back is wired to the same close path, so
 * the two agree.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { Animated, BackHandler, Easing, StyleSheet, useWindowDimensions, View } from 'react-native';
import type { CheckId, NativeEngineInfo, SecurityReport } from 'react-native-security-toolkit';
import { useTheme } from '../theme/theme';
import { ChecksScreen } from '../screens/ChecksScreen';
import { CheckDetailScreen } from '../screens/CheckDetailScreen';
import { EngineScreen } from '../screens/EngineScreen';
import { OverviewScreen } from '../screens/OverviewScreen';
import { PolicyScreen } from '../screens/PolicyScreen';
import { SignalsScreen } from '../screens/SignalsScreen';
import { TabBar, type TabName } from './TabBar';

export function AppNavigator({
  report,
  engine,
}: {
  readonly report: SecurityReport;
  readonly engine: NativeEngineInfo;
}) {
  const { palette } = useTheme();
  const { width } = useWindowDimensions();
  const [tab, setTab] = useState<TabName>('overview');
  const [detail, setDetail] = useState<CheckId | undefined>(undefined);
  const slide = useRef(new Animated.Value(0)).current;

  const open = useCallback(
    (id: CheckId) => {
      setDetail(id);
      Animated.timing(slide, {
        toValue: 1,
        duration: 260,
        easing: Easing.out(Easing.cubic),
        useNativeDriver: true,
      }).start();
    },
    [slide]
  );

  const close = useCallback(() => {
    Animated.timing(slide, {
      toValue: 0,
      duration: 200,
      easing: Easing.in(Easing.cubic),
      useNativeDriver: true,
    }).start(({ finished }) => {
      if (finished) {
        setDetail(undefined);
      }
    });
  }, [slide]);

  useEffect(() => {
    if (detail === undefined) {
      return undefined;
    }
    const subscription = BackHandler.addEventListener('hardwareBackPress', () => {
      close();
      return true;
    });
    return () => subscription.remove();
  }, [close, detail]);

  return (
    <View style={[styles.root, { backgroundColor: palette.background }]}>
      {tab === 'overview' ? <OverviewScreen report={report} onOpenCheck={open} /> : null}
      {tab === 'checks' ? <ChecksScreen report={report} onOpenCheck={open} /> : null}
      {tab === 'signals' ? <SignalsScreen report={report} /> : null}
      {tab === 'policy' ? <PolicyScreen report={report} /> : null}
      {tab === 'engine' ? <EngineScreen engine={engine} report={report} /> : null}

      <TabBar active={tab} onSelect={setTab} />

      {detail === undefined ? null : (
        <Animated.View
          style={[
            styles.overlay,
            {
              backgroundColor: palette.background,
              transform: [
                {
                  translateX: slide.interpolate({
                    inputRange: [0, 1],
                    outputRange: [width, 0],
                  }),
                },
              ],
            },
          ]}
        >
          <CheckDetailScreen id={detail} report={report} onBack={close} />
        </Animated.View>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  root: {
    flex: 1,
  },
  overlay: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
  },
});
