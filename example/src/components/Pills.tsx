/**
 * Status indicators.
 *
 * Every one of these pairs colour with a glyph or a word. A status conveyed by
 * hue alone is unreadable to a colour-blind user and vanishes in a greyscale
 * screenshot — and these five statuses are exactly the distinctions the toolkit
 * refuses to blur in its types, so the UI must not blur them either.
 */

import { StyleSheet, View } from 'react-native';
import type {
  SecurityCheckResult,
  SecurityConfidence,
  SignalOutcome,
} from 'react-native-security-toolkit';
import { useTheme } from '../theme/theme';
import { radius, space } from '../theme/tokens';
import { CONFIDENCE_LABEL, OUTCOME_LABEL, STATUS } from '../security/catalog';
import { Caption, Label } from './Typography';
import type { IconComponent } from '../icons';

/** Status pill for a check result: tinted background, glyph and word. */
export function StatusPill({
  status,
  size = 'md',
}: {
  readonly status: SecurityCheckResult['status'];
  readonly size?: 'sm' | 'md' | undefined;
}) {
  const { palette } = useTheme();
  const meta = STATUS[status];
  const Glyph = meta.icon;
  const color = palette.status[status];

  return (
    <View
      style={[
        styles.pill,
        size === 'sm' ? styles.pillSm : null,
        { backgroundColor: palette.statusSoft[status] },
      ]}
    >
      <Glyph size={size === 'sm' ? 11 : 13} color={color} strokeWidth={2} />
      <Label color={color}>{meta.label}</Label>
    </View>
  );
}

/** Neutral chip for platform badges, check names and counts. */
export function Chip({
  label,
  color,
  icon: Glyph,
  tint,
}: {
  readonly label: string;
  readonly color?: string | undefined;
  readonly icon?: IconComponent | undefined;
  readonly tint?: string | undefined;
}) {
  const { palette } = useTheme();
  const resolved = color ?? palette.textMuted;
  return (
    <View
      style={[
        styles.chip,
        { backgroundColor: tint ?? palette.surfaceRaised, borderColor: palette.border },
      ]}
    >
      {Glyph === undefined ? null : <Glyph size={12} color={resolved} strokeWidth={2} />}
      <Caption color={resolved}>{label}</Caption>
    </View>
  );
}

/**
 * Confidence as three bars.
 *
 * Shown next to a verdict rather than inside it, because confidence describes
 * the strength of the evidence and not the seriousness of the finding.
 */
export function ConfidenceMeter({
  confidence,
  color,
  showLabel = true,
}: {
  readonly confidence: SecurityConfidence;
  readonly color?: string | undefined;
  readonly showLabel?: boolean | undefined;
}) {
  const { palette } = useTheme();
  const filled = confidence === 'high' ? 3 : confidence === 'medium' ? 2 : 1;
  const resolved = color ?? palette.textMuted;

  return (
    <View style={styles.meter}>
      <View style={styles.bars}>
        {[0, 1, 2].map((index) => (
          <View
            key={index}
            style={[
              styles.bar,
              { backgroundColor: index < filled ? resolved : palette.track },
              index === 1 ? styles.barMid : null,
              index === 2 ? styles.barTall : null,
            ]}
          />
        ))}
      </View>
      {showLabel ? <Caption tone="muted">{CONFIDENCE_LABEL[confidence]}</Caption> : null}
    </View>
  );
}

/** Dot plus word for a single signal's outcome. */
export function OutcomeTag({ outcome }: { readonly outcome: SignalOutcome }) {
  const { palette } = useTheme();
  const color = palette.outcome[outcome];
  return (
    <View style={styles.outcome}>
      <View style={[styles.dot, { backgroundColor: color }]} />
      <Label color={color}>{OUTCOME_LABEL[outcome]}</Label>
    </View>
  );
}

/** Tinted rounded square holding a check's icon. The list's visual anchor. */
export function IconBadge({
  icon: Glyph,
  color,
  tint,
  size = 40,
}: {
  readonly icon: IconComponent;
  readonly color: string;
  readonly tint: string;
  readonly size?: number | undefined;
}) {
  return (
    <View
      style={[
        styles.badge,
        { width: size, height: size, borderRadius: size / 3.2, backgroundColor: tint },
      ]}
    >
      <Glyph size={size * 0.52} color={color} strokeWidth={1.8} />
    </View>
  );
}

const styles = StyleSheet.create({
  pill: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: space.xs,
    paddingHorizontal: space.sm,
    paddingVertical: 5,
    borderRadius: radius.pill,
  },
  pillSm: {
    paddingHorizontal: 6,
    paddingVertical: 3,
  },
  chip: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: space.xs,
    paddingHorizontal: space.sm,
    paddingVertical: 4,
    borderRadius: radius.pill,
    borderWidth: StyleSheet.hairlineWidth,
  },
  meter: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: space.sm,
  },
  bars: {
    flexDirection: 'row',
    alignItems: 'flex-end',
    gap: 2,
  },
  bar: {
    width: 3,
    height: 6,
    borderRadius: 2,
  },
  barMid: {
    height: 9,
  },
  barTall: {
    height: 12,
  },
  outcome: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: space.xs,
  },
  dot: {
    width: 6,
    height: 6,
    borderRadius: 3,
  },
  badge: {
    alignItems: 'center',
    justifyContent: 'center',
  },
});
