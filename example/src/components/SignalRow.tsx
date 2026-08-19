/**
 * One detection signal.
 *
 * A signal row shows four things, and all four matter to someone deciding how
 * much to trust a verdict: the stable identifier, what it concluded, how strong
 * that evidence is on its own, and what it cost in risk points. Metadata is
 * collapsed by default — it is detector-specific detail, useful when you are
 * investigating a specific signal and noise when you are not.
 */

import { useState } from 'react';
import { StyleSheet, View } from 'react-native';
import type { RiskContributor, SecuritySignal } from 'react-native-security-toolkit';
import { useTheme } from '../theme/theme';
import { radius, space } from '../theme/tokens';
import { CHECKS } from '../security/catalog';
import { formatMetadataValue, formatPoints } from '../security/derive';
import { PressableRow } from './Controls';
import { Chip, ConfidenceMeter, OutcomeTag } from './Pills';
import { Body, Caption, Mono } from './Typography';
import { ChevronDownIcon, ChevronRightIcon } from '../icons';
import type { CheckId } from 'react-native-security-toolkit';

export function SignalRow({
  signal,
  contributor,
  checkId,
  first = false,
}: {
  readonly signal: SecuritySignal;
  readonly contributor?: RiskContributor | undefined;
  /** Shown as a chip when the row appears outside its own check's screen. */
  readonly checkId?: CheckId | undefined;
  /** Suppresses the separator above the first row in a card. */
  readonly first?: boolean | undefined;
}) {
  const { palette } = useTheme();
  const [open, setOpen] = useState(false);
  const color = palette.outcome[signal.outcome];
  const metadata = Object.entries(signal.metadata ?? {});
  const expandable = metadata.length > 0;

  return (
    <View style={[first ? styles.wrapFirst : styles.wrap, { borderColor: palette.border }]}>
      <PressableRow onPress={() => setOpen((current) => !current)}>
        <View style={styles.head}>
          <View style={[styles.rail, { backgroundColor: color }]} />
          <View style={styles.headText}>
            <View style={styles.headTop}>
              <Mono color={color} style={styles.id}>
                {signal.id}
              </Mono>
              {contributor === undefined ? null : (
                <Chip
                  label={`${formatPoints(contributor.points)} pts`}
                  color={contributor.points > 0 ? palette.status.detected : palette.status.secure}
                />
              )}
            </View>
            <Body tone="muted">{signal.description}</Body>
            <View style={styles.meta}>
              <OutcomeTag outcome={signal.outcome} />
              <ConfidenceMeter confidence={signal.confidence} showLabel={false} />
              {checkId === undefined ? null : <Chip label={CHECKS[checkId].title} />}
            </View>
          </View>
          {expandable ? (
            open ? (
              <ChevronDownIcon size={15} color={palette.textFaint} />
            ) : (
              <ChevronRightIcon size={15} color={palette.textFaint} />
            )
          ) : null}
        </View>
      </PressableRow>

      {open && expandable ? (
        <View style={[styles.metadata, { backgroundColor: palette.surfaceRaised }]}>
          {metadata.map(([key, value]) => (
            <View key={key} style={styles.metaRow}>
              <Caption tone="faint" style={styles.metaKey}>
                {key}
              </Caption>
              <Mono tone="muted" style={styles.metaValue}>
                {formatMetadataValue(value)}
              </Mono>
            </View>
          ))}
        </View>
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: {
    borderTopWidth: StyleSheet.hairlineWidth,
    paddingTop: space.md,
    marginTop: space.md,
  },
  wrapFirst: {
    paddingTop: space.xs,
  },
  head: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: space.md,
  },
  rail: {
    width: 3,
    borderRadius: 2,
    alignSelf: 'stretch',
    minHeight: 34,
  },
  headText: {
    flex: 1,
    gap: space.xs,
  },
  headTop: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: space.sm,
  },
  id: {
    flexShrink: 1,
  },
  meta: {
    flexDirection: 'row',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: space.sm,
    marginTop: 2,
  },
  metadata: {
    marginTop: space.md,
    padding: space.md,
    borderRadius: radius.md,
    gap: space.sm,
  },
  metaRow: {
    gap: 2,
  },
  metaKey: {
    textTransform: 'none',
  },
  metaValue: {
    flexShrink: 1,
  },
});
