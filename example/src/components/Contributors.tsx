/**
 * The arithmetic behind a risk score.
 *
 * The brief is explicit about this and it is the right call: a score must never
 * appear without its contributors. Positive points are drawn from the centre to
 * the right, mitigation credits to the left, so a glance shows what pushed the
 * number up and what pulled it down.
 */

import { StyleSheet, View } from 'react-native';
import type { RiskContributor } from 'react-native-security-toolkit';
import { useTheme } from '../theme/theme';
import { space } from '../theme/tokens';
import { formatPoints } from '../security/derive';
import { Caption, Mono } from './Typography';

export function ContributorRow({
  contributor,
  scale,
}: {
  readonly contributor: RiskContributor;
  /** Largest absolute points in the set, so bars are comparable to each other. */
  readonly scale: number;
}) {
  const { palette } = useTheme();
  const positive = contributor.points > 0;
  const color = positive ? palette.status.detected : palette.status.secure;
  const width =
    `${Math.max(6, (Math.abs(contributor.points) / Math.max(scale, 1)) * 100)}%` as const;

  return (
    <View style={styles.row}>
      <View style={styles.head}>
        <Mono tone="muted" style={styles.source} numberOfLines={1}>
          {contributor.source}
        </Mono>
        <Mono color={color}>{`${formatPoints(contributor.points)} pts`}</Mono>
      </View>
      <View style={[styles.track, { backgroundColor: palette.track }]}>
        <View
          style={[
            styles.fill,
            { width, backgroundColor: color },
            positive ? styles.fillPositive : styles.fillNegative,
          ]}
        />
      </View>
      <Caption tone="faint" numberOfLines={2}>
        {contributor.reason}
      </Caption>
    </View>
  );
}

const styles = StyleSheet.create({
  row: {
    gap: space.xs,
  },
  head: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: space.sm,
  },
  source: {
    flexShrink: 1,
  },
  track: {
    height: 5,
    borderRadius: 3,
    overflow: 'hidden',
    flexDirection: 'row',
  },
  fill: {
    height: 5,
    borderRadius: 3,
  },
  fillPositive: {
    alignSelf: 'flex-start',
  },
  fillNegative: {
    alignSelf: 'flex-end',
  },
});
