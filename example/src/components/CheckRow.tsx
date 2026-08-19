/**
 * A check as a list row, and as a grid tile.
 *
 * Both carry icon, name, status word and status colour. The tile is used on the
 * posture grid where scanning eleven checks at once matters; the row is used
 * where the signal counts matter more than density.
 */

import { StyleSheet, View } from 'react-native';
import type { SecurityCheckResult } from 'react-native-security-toolkit';
import { useTheme } from '../theme/theme';
import { space } from '../theme/tokens';
import { CHECKS, UNAVAILABLE_REASONS } from '../security/catalog';
import { describeTally, tally } from '../security/derive';
import { Card } from './Card';
import { PressableRow } from './Controls';
import { Chip, IconBadge, StatusPill } from './Pills';
import { BodyStrong, Caption } from './Typography';
import { ChevronRightIcon } from '../icons';

export function CheckRow({
  result,
  onPress,
}: {
  readonly result: SecurityCheckResult;
  readonly onPress: () => void;
}) {
  const { palette } = useTheme();
  const meta = CHECKS[result.id];
  const color = palette.status[result.status];
  const counts = tally(result.signals);

  return (
    <PressableRow onPress={onPress}>
      <View style={styles.row}>
        <IconBadge icon={meta.icon} color={color} tint={palette.statusSoft[result.status]} />
        <View style={styles.rowText}>
          <View style={styles.rowTop}>
            <BodyStrong numberOfLines={1} style={styles.rowTitle}>
              {meta.title}
            </BodyStrong>
            <StatusPill status={result.status} size="sm" />
          </View>
          <Caption tone="muted" numberOfLines={1}>
            {result.status === 'unavailable' && result.unavailableReason !== undefined
              ? UNAVAILABLE_REASONS[result.unavailableReason]
              : describeTally(counts)}
          </Caption>
        </View>
        <ChevronRightIcon size={16} color={palette.textFaint} />
      </View>
    </PressableRow>
  );
}

/** Compact tile for the posture grid. Two per row. */
export function CheckTile({
  result,
  onPress,
}: {
  readonly result: SecurityCheckResult;
  readonly onPress: () => void;
}) {
  const { palette } = useTheme();
  const meta = CHECKS[result.id];
  const color = palette.status[result.status];
  const counts = tally(result.signals);
  const muted = result.status === 'unavailable';

  return (
    <PressableRow onPress={onPress} style={styles.tileWrap}>
      <Card style={styles.tile} accent={muted ? undefined : color}>
        <View style={styles.tileTop}>
          <IconBadge
            icon={meta.icon}
            color={muted ? palette.textFaint : color}
            tint={palette.statusSoft[result.status]}
            size={32}
          />
          <StatusPill status={result.status} size="sm" />
        </View>
        <BodyStrong numberOfLines={2}>{meta.title}</BodyStrong>
        <Caption tone="faint" numberOfLines={1}>
          {muted ? 'not run here' : `${counts.fired}/${counts.total} signals fired`}
        </Caption>
      </Card>
    </PressableRow>
  );
}

/** Platform badges for a check, e.g. "android" / "ios". */
export function PlatformChips({ id }: { readonly id: SecurityCheckResult['id'] }) {
  return (
    <View style={styles.chips}>
      {CHECKS[id].platforms.map((platform) => (
        <Chip key={platform} label={platform} />
      ))}
    </View>
  );
}

const styles = StyleSheet.create({
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: space.md,
    paddingVertical: space.sm,
  },
  rowText: {
    flex: 1,
    gap: 3,
  },
  rowTop: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: space.sm,
  },
  rowTitle: {
    flex: 1,
  },
  // Fixed at half the row rather than flex-grown: a lone tile on the last row
  // stretching to full width reads as a different kind of card, when it is just
  // the eleventh of eleven.
  tileWrap: {
    width: '48.5%',
  },
  tile: {
    gap: space.sm,
    padding: space.md,
    minHeight: 116,
  },
  tileTop: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: space.xs,
  },
  chips: {
    flexDirection: 'row',
    gap: space.xs,
  },
});
