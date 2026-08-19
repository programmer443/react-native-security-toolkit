/**
 * Posture overview — the screen a reader sees first.
 *
 * It answers three questions in order: what is the score, why is it that score,
 * and which check should I look at. The middle one is the reason the contributor
 * list sits above the check grid rather than buried in a detail view: a score
 * without its arithmetic is not actionable, and the brief forbids showing one.
 */

import { useState } from 'react';
import { StyleSheet, View } from 'react-native';
import type { CheckId, SecurityReport } from 'react-native-security-toolkit';
import { useTheme } from '../theme/theme';
import { radius, space } from '../theme/tokens';
import { DEFENCE_IN_DEPTH_NOTE, RISK_LEVELS } from '../security/catalog';
import {
  bySeverity,
  formatDuration,
  formatTime,
  orderedChecks,
  summarise,
  type ReportSummary,
} from '../security/derive';
import { useSecurity } from '../security/SecurityProvider';
import { fireAndForget } from '../utils/async';
import { Card, KeyValue, SectionHeader } from '../components/Card';
import { CheckTile } from '../components/CheckRow';
import { ContributorRow } from '../components/Contributors';
import { GhostButton, IconButton, Note } from '../components/Controls';
import { Chip } from '../components/Pills';
import { RiskGauge } from '../components/RiskGauge';
import { Screen } from '../components/Screen';
import { BodyStrong, Caption, Label, Mono, textStyles } from '../components/Typography';
import {
  AlertTriangleIcon,
  ChevronDownIcon,
  ClockIcon,
  InfoIcon,
  RefreshIcon,
  ZapIcon,
} from '../icons';

const COLLAPSED_CONTRIBUTORS = 4;

export function OverviewScreen({
  report,
  onOpenCheck,
}: {
  readonly report: SecurityReport;
  readonly onOpenCheck: (id: CheckId) => void;
}) {
  const { palette } = useTheme();
  const { refresh, refreshing, developmentMode } = useSecurity();
  const [showAll, setShowAll] = useState(false);

  const summary = summarise(report);
  const level = RISK_LEVELS[report.risk.level];
  const levelColor = palette.risk[report.risk.level];
  const checks = [...orderedChecks(report)].sort(bySeverity);
  const contributors = showAll
    ? report.risk.contributors
    : report.risk.contributors.slice(0, COLLAPSED_CONTRIBUTORS);
  const scale = report.risk.contributors.reduce(
    (max, contributor) => Math.max(max, Math.abs(contributor.points)),
    1
  );

  return (
    <Screen
      kicker="Security toolkit"
      title="Device posture"
      subtitle={`${report.platform} · engine ${report.engineVersion} · ${formatDuration(report.durationMs)}`}
      refreshing={refreshing}
      onRefresh={fireAndForget(refresh)}
      action={
        <IconButton
          icon={RefreshIcon}
          onPress={fireAndForget(refresh)}
          label="Re-run all checks"
          busy={refreshing}
        />
      }
    >
      <Card style={styles.hero}>
        <View style={styles.gauge}>
          <RiskGauge score={report.risk.score} level={report.risk.level} />
        </View>

        <View style={styles.verdict}>
          <BodyStrong color={levelColor} style={textStyles.center}>
            {headline(report, summary)}
          </BodyStrong>
          <Caption tone="muted" style={textStyles.center}>
            {level.advice}
          </Caption>
        </View>

        <View style={[styles.stats, { borderTopColor: palette.border }]}>
          <Stat value={summary.checksRun} label="checks run" />
          <Stat
            value={summary.signals.fired}
            label="signals fired"
            color={summary.signals.fired > 0 ? palette.status.detected : undefined}
          />
          <Stat
            value={summary.signals.inconclusive}
            label="unclear"
            color={summary.signals.inconclusive > 0 ? palette.status.unknown : undefined}
          />
          <Stat value={summary.unavailable} label="not applicable" color={palette.textFaint} />
        </View>
      </Card>

      {developmentMode ? (
        <Card style={styles.banner} tint={palette.accentSoft} accent={palette.accent}>
          <Note icon={InfoIcon} tone={palette.accent}>
            Development mode is on. Debugger, emulator and simulator signals are excluded from this
            score — the findings underneath are unchanged.
          </Note>
        </Card>
      ) : null}

      <SectionHeader
        title="Why this score"
        hint={`Score is the sum of every contributor, clamped to 0–100. Methodology ${report.risk.methodologyVersion}.`}
      />
      <Card style={styles.contributors}>
        {report.risk.contributors.length === 0 ? (
          <Note icon={ZapIcon}>
            Nothing scored. No indicators fired, and no mitigation credits applied on this platform.
          </Note>
        ) : (
          <>
            {contributors.map((contributor) => (
              <ContributorRow
                key={`${contributor.source}-${contributor.points}`}
                contributor={contributor}
                scale={scale}
              />
            ))}
            {report.risk.contributors.length > COLLAPSED_CONTRIBUTORS ? (
              <GhostButton
                label={
                  showAll
                    ? 'Show top contributors only'
                    : `Show all ${report.risk.contributors.length} contributors`
                }
                icon={ChevronDownIcon}
                onPress={() => setShowAll((current) => !current)}
              />
            ) : null}
          </>
        )}
      </Card>

      <SectionHeader title="Posture" hint="Ordered by what needs attention. Tap for signals." />
      <View style={styles.grid}>
        {checks.map((result) => (
          <CheckTile key={result.id} result={result} onPress={() => onOpenCheck(result.id)} />
        ))}
      </View>

      <SectionHeader title="This run" />
      <Card>
        <KeyValue label="Platform" value={report.platform} />
        <KeyValue label="Engine version" value={report.engineVersion} />
        <KeyValue label="Aggregate duration" value={formatDuration(report.durationMs)} />
        <KeyValue label="Completed" value={formatTime(report.checkedAt)} />
        <View style={styles.chips}>
          <Chip label={`${report.risk.methodologyVersion}`} icon={ZapIcon} />
          <Chip label={formatTime(report.checkedAt)} icon={ClockIcon} />
          {report.compromised ? (
            <Chip
              label="compromised flag set"
              icon={AlertTriangleIcon}
              color={palette.status.detected}
              tint={palette.statusSoft.detected}
            />
          ) : null}
        </View>
      </Card>

      <Card style={styles.disclaimer} tint={palette.surfaceRaised}>
        <Note icon={InfoIcon}>{DEFENCE_IN_DEPTH_NOTE}</Note>
      </Card>
    </Screen>
  );
}

/**
 * The one line that states what happened, without pre-empting the band advice
 * printed under it. Counting checks rather than restating the level keeps the
 * two from contradicting each other — "indicators present" above "no meaningful
 * indicators" reads as a bug in the risk engine.
 */
function headline(report: SecurityReport, summary: ReportSummary): string {
  if (report.compromised) {
    return 'Indicators consistent with a compromised environment';
  }
  if (summary.detected > 0) {
    return `${summary.detected} of ${summary.checksRun} checks reported indicators`;
  }
  if (summary.inconclusive > 0) {
    return 'No indicators fired, but not every probe could answer';
  }
  return 'No indicators fired on this device';
}

function Stat({
  value,
  label,
  color,
}: {
  readonly value: number;
  readonly label: string;
  readonly color?: string | undefined;
}) {
  return (
    <View style={styles.stat}>
      <Mono color={color} style={styles.statValue}>
        {String(value)}
      </Mono>
      <Label tone="faint" style={styles.statLabel}>
        {label}
      </Label>
    </View>
  );
}

const styles = StyleSheet.create({
  hero: {
    gap: space.lg,
    paddingTop: space.xl,
  },
  gauge: {
    alignItems: 'center',
  },
  verdict: {
    gap: space.xs,
    paddingHorizontal: space.xs,
  },
  stats: {
    flexDirection: 'row',
    // Without a gap the labels of adjacent columns touch once they fit on one
    // line, and "signals fired inconclusive" reads as one phrase.
    gap: space.sm,
    borderTopWidth: StyleSheet.hairlineWidth,
    paddingTop: space.md,
  },
  stat: {
    flex: 1,
    alignItems: 'center',
    gap: 3,
  },
  statLabel: {
    textAlign: 'center',
    fontSize: 10,
    letterSpacing: 0.2,
  },
  statValue: {
    fontSize: 19,
    lineHeight: 23,
    fontWeight: '700',
    fontVariant: ['tabular-nums'],
  },
  banner: {
    marginTop: space.md,
  },
  contributors: {
    gap: space.lg,
  },
  grid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
    rowGap: space.md,
  },
  chips: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: space.xs,
  },
  disclaimer: {
    marginTop: space.lg,
    borderRadius: radius.md,
  },
});
