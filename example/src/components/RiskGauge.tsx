/**
 * Risk score as a 270° gauge.
 *
 * A gauge is used rather than a big red number because the score is bounded and
 * banded: 0–100 with five named levels. The arc shows where in that range the
 * device sits, which a bare number does not.
 *
 * The score is never shown alone — the level word sits under it, and the screen
 * that hosts this always shows the arithmetic behind it. A number nobody can
 * account for is a number nobody should act on.
 */

import { useEffect, useRef, useState } from 'react';
import { Animated, Easing, StyleSheet, View } from 'react-native';
import Svg, { Path } from 'react-native-svg';
import type { RiskLevel } from 'react-native-security-toolkit';
import { useTheme } from '../theme/theme';
import { space } from '../theme/tokens';
import { RISK_LEVELS } from '../security/catalog';
import { formatScore } from '../security/derive';
import { Caption, Label } from './Typography';

const AnimatedPath = Animated.createAnimatedComponent(Path);

const START_ANGLE = 135;
const SWEEP = 270;

export function RiskGauge({
  score,
  level,
  size = 168,
  thickness = 13,
}: {
  readonly score: number;
  readonly level: RiskLevel;
  readonly size?: number | undefined;
  readonly thickness?: number | undefined;
}) {
  const { palette } = useTheme();
  const color = palette.risk[level];
  const radius = (size - thickness) / 2 - 2;
  const centre = size / 2;
  const arc = describeArc(centre, radius, START_ANGLE, SWEEP);
  const length = (2 * Math.PI * radius * SWEEP) / 360;

  const progress = useRef(new Animated.Value(0)).current;
  const [shown, setShown] = useState(0);

  useEffect(() => {
    const id = progress.addListener(({ value }) => setShown(value * score));
    progress.setValue(0);
    Animated.timing(progress, {
      toValue: 1,
      duration: 900,
      easing: Easing.out(Easing.cubic),
      // strokeDashoffset is not a transform, so this cannot run on the native
      // driver. One animated property for under a second is an acceptable cost.
      useNativeDriver: false,
    }).start();
    return () => progress.removeListener(id);
  }, [progress, score]);

  const offset = progress.interpolate({
    inputRange: [0, 1],
    outputRange: [length, length * (1 - clamp01(score / 100))],
  });

  return (
    <View style={[styles.wrap, { width: size, height: size }]}>
      <Svg width={size} height={size}>
        <Path
          d={arc}
          stroke={palette.track}
          strokeWidth={thickness}
          strokeLinecap="round"
          fill="none"
        />
        <AnimatedPath
          d={arc}
          stroke={color}
          strokeWidth={thickness}
          strokeLinecap="round"
          fill="none"
          strokeDasharray={`${length} ${length}`}
          strokeDashoffset={offset}
        />
      </Svg>

      <View style={styles.centre} pointerEvents="none">
        <Caption tone="faint">RISK SCORE</Caption>
        <Animated.Text style={[styles.score, { color: palette.text }]}>
          {formatScore(shown)}
        </Animated.Text>
        <Label color={color}>{RISK_LEVELS[level].label}</Label>
      </View>
    </View>
  );
}

function pointOnArc(centre: number, radius: number, angle: number) {
  const radians = (angle * Math.PI) / 180;
  return { x: centre + radius * Math.cos(radians), y: centre + radius * Math.sin(radians) };
}

function describeArc(centre: number, radius: number, start: number, sweep: number): string {
  const from = pointOnArc(centre, radius, start);
  const to = pointOnArc(centre, radius, start + sweep);
  const largeArc = sweep > 180 ? 1 : 0;
  return `M ${from.x} ${from.y} A ${radius} ${radius} 0 ${largeArc} 1 ${to.x} ${to.y}`;
}

function clamp01(value: number): number {
  return Math.max(0, Math.min(1, value));
}

const styles = StyleSheet.create({
  wrap: {
    alignItems: 'center',
    justifyContent: 'center',
  },
  centre: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    alignItems: 'center',
    justifyContent: 'center',
    gap: space.xxs,
  },
  score: {
    fontSize: 42,
    lineHeight: 46,
    fontWeight: '800',
    fontVariant: ['tabular-nums'],
  },
});
