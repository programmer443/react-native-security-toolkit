/**
 * One check in full: verdict, evidence, and what the check cannot tell you.
 *
 * The caveat is not a footnote here. Every detector in this toolkit has
 * conditions under which it produces a false positive or misses entirely, and a
 * screen that shows a red badge without them invites exactly the overreaction
 * the project brief forbids — blocking a developer with an unlocked bootloader,
 * or a QA rig on an emulator.
 *
 * The re-run button deliberately goes through the focused single-check module
 * rather than `checkAll()`, then re-scores with the public `evaluateRisk()`.
 */

import { useCallback, useState } from 'react';
import { StyleSheet, View } from 'react-native';
import type { CheckId, SecurityReport, SecuritySignal } from 'react-native-security-toolkit';
import { useTheme } from '../theme/theme';
import { radius, space } from '../theme/tokens';
import { CHECKS, CONFIDENCE_HINT, STATUS, UNAVAILABLE_REASONS } from '../security/catalog';
import {
  contributorIndex,
  formatDuration,
  formatMetadataValue,
  formatPoints,
  formatTime,
  pointsForCheck,
  tally,
} from '../security/derive';
import { useSecurity } from '../security/SecurityProvider';
import { fireAndForget } from '../utils/async';
import { Card, Divider, KeyValue, SectionHeader } from '../components/Card';
import { PlatformChips } from '../components/CheckRow';
import { GhostButton, IconButton, Note, Paragraph, PrimaryButton } from '../components/Controls';
import { Chip, ConfidenceMeter, IconBadge, StatusPill } from '../components/Pills';
import { Screen } from '../components/Screen';
import { SignalRow } from '../components/SignalRow';
import { Body, BodyStrong, Caption, Mono } from '../components/Typography';
import { AlertTriangleIcon, ChevronDownIcon, InfoIcon, PlayIcon, RefreshIcon } from '../icons';

const KIND_LABEL = {
  threat: 'Threat detection',
  environment: 'Environment',
  capability: 'Capability report',
} as const;

export function CheckDetailScreen({
  id,
  report,
  onBack,
}: {
  readonly id: CheckId;
  readonly report: SecurityReport;
  readonly onBack: () => void;
}) {
  const { palette } = useTheme();
  const { rerunCheck } = useSecurity();
  const [busy, setBusy] = useState(false);
  const [rerunAt, setRerunAt] = useState<string | undefined>(undefined);
  const [showClear, setShowClear] = useState(false);

  const result = report.checks[id];
  const meta = CHECKS[id];

  const rerun = useCallback(async () => {
    setBusy(true);
    try {
      const fresh = await rerunCheck(id);
      setRerunAt(fresh?.checkedAt);
    } finally {
      setBusy(false);
    }
  }, [id, rerunCheck]);

  if (result === undefined) {
    // Absence is meaningful: this platform's engine does not implement the check
    // at all, which is different from implementing it and reporting unavailable.
    return (
      <Screen kicker={KIND_LABEL[meta.kind]} title={meta.title} onBack={onBack} withTabBar={false}>
        <Card>
          <Note icon={InfoIcon}>
            This platform's engine does not implement this check, so the report omits it entirely
            rather than inventing a result for it.
          </Note>
          <PlatformChips id={id} />
        </Card>
      </Screen>
    );
  }

  const status = STATUS[result.status];
  const color = palette.status[result.status];
  const counts = tally(result.signals);
  const contributors = contributorIndex(report);
  const points = pointsForCheck(report, id);
  const metadata = Object.entries(result.metadata ?? {});

  const fired = result.signals.filter((signal) => signal.outcome === 'detected');
  const inconclusive = result.signals.filter((signal) => signal.outcome === 'indeterminate');
  const clear = result.signals.filter((signal) => signal.outcome === 'not-detected');

  return (
    <Screen
      kicker={KIND_LABEL[meta.kind]}
      title={meta.title}
      onBack={onBack}
      withTabBar={false}
      action={
        <IconButton icon={RefreshIcon} onPress={fireAndForget(rerun)} label="Re-run" busy={busy} />
      }
    >
      <Card accent={color} style={styles.verdict}>
        <View style={styles.verdictHead}>
          <IconBadge
            icon={meta.icon}
            color={color}
            tint={palette.statusSoft[result.status]}
            size={46}
          />
          <View style={styles.verdictHeadText}>
            <StatusPill status={result.status} />
            <ConfidenceMeter confidence={result.confidence} color={color} />
          </View>
        </View>

        <Body tone="muted">{status.explain(meta.kind)}</Body>

        {result.status === 'unavailable' && result.unavailableReason !== undefined ? (
          <Note icon={InfoIcon}>
            {`${result.unavailableReason} — ${UNAVAILABLE_REASONS[result.unavailableReason]}`}
          </Note>
        ) : null}

        {result.errorMessage === undefined ? null : (
          <View style={[styles.errorBox, { backgroundColor: palette.statusSoft.error }]}>
            <Mono color={palette.status.error}>{result.errorMessage}</Mono>
          </View>
        )}

        <Divider />

        <View style={styles.metrics}>
          <Metric
            label="signals fired"
            value={`${counts.fired}/${counts.total}`}
            color={counts.fired > 0 ? color : undefined}
          />
          <Metric
            label="risk points"
            value={formatPoints(points)}
            color={
              points > 0 ? palette.status.detected : points < 0 ? palette.status.secure : undefined
            }
          />
          <Metric label="duration" value={formatDuration(result.durationMs)} />
          <Metric label="checked" value={formatTime(rerunAt ?? result.checkedAt)} />
        </View>
      </Card>

      <SectionHeader title="What this checks" />
      <Card>
        <Paragraph>{meta.summary}</Paragraph>
        <Note icon={AlertTriangleIcon} tone={palette.status.unknown}>
          {meta.caveat}
        </Note>
        <View style={styles.docsRow}>
          <PlatformChips id={id} />
          <Chip label={meta.docs} />
        </View>
      </Card>

      {fired.length > 0 ? (
        <>
          <SectionHeader
            title={`Fired · ${fired.length}`}
            hint="Evidence behind the verdict. Weigh these rather than the verdict alone."
          />
          <Card style={styles.signals}>
            <SignalList signals={fired} contributors={contributors} />
          </Card>
        </>
      ) : null}

      {inconclusive.length > 0 ? (
        <>
          <SectionHeader
            title={`Inconclusive · ${inconclusive.length}`}
            hint="Probes that could not reach an answer. Not counted as evidence of safety."
          />
          <Card style={styles.signals}>
            <SignalList signals={inconclusive} contributors={contributors} />
          </Card>
        </>
      ) : null}

      {clear.length > 0 ? (
        <>
          <SectionHeader title={`Clear · ${clear.length}`} />
          <Card style={styles.signals}>
            {showClear ? (
              <SignalList signals={clear} contributors={contributors} />
            ) : (
              <Caption tone="muted">
                {`${clear.length} signals ran and found nothing. Every signal is returned, including the quiet ones, so a verdict can be audited rather than trusted.`}
              </Caption>
            )}
            <GhostButton
              label={showClear ? 'Hide clear signals' : `Show ${clear.length} clear signals`}
              icon={ChevronDownIcon}
              onPress={() => setShowClear((current) => !current)}
            />
          </Card>
        </>
      ) : null}

      {metadata.length > 0 ? (
        <>
          <SectionHeader
            title="Check metadata"
            hint="Capabilities, versions and configuration echoes."
          />
          <Card>
            {metadata.map(([key, value]) => (
              <KeyValue key={key} label={key} value={formatMetadataValue(value)} wrap />
            ))}
          </Card>
        </>
      ) : null}

      <SectionHeader title="Run it again" />
      <Card>
        <Paragraph>
          Runs this check through its own module — the focused API a screen would call when it needs
          one answer — then re-scores the report with the public risk engine.
        </Paragraph>
        <PrimaryButton
          label={`Re-run ${meta.title.toLowerCase()}`}
          icon={PlayIcon}
          onPress={fireAndForget(rerun)}
          busy={busy}
        />
        {rerunAt === undefined ? null : (
          <Caption tone="faint">{`Last re-run at ${formatTime(rerunAt)}.`}</Caption>
        )}
        <Note icon={InfoIcon}>{CONFIDENCE_HINT}</Note>
      </Card>
    </Screen>
  );
}

function SignalList({
  signals,
  contributors,
}: {
  readonly signals: readonly SecuritySignal[];
  readonly contributors: ReadonlyMap<
    string,
    { readonly points: number; readonly reason: string; readonly source: string }
  >;
}) {
  return (
    <>
      {signals.map((signal, index) => {
        const contributor = contributors.get(signal.id);
        return (
          <SignalRow
            key={signal.id}
            signal={signal}
            first={index === 0}
            contributor={contributor}
          />
        );
      })}
    </>
  );
}

function Metric({
  label,
  value,
  color,
}: {
  readonly label: string;
  readonly value: string;
  readonly color?: string | undefined;
}) {
  return (
    <View style={styles.metric}>
      <BodyStrong color={color} style={styles.metricValue}>
        {value}
      </BodyStrong>
      <Caption tone="faint">{label}</Caption>
    </View>
  );
}

const styles = StyleSheet.create({
  verdict: {
    gap: space.md,
  },
  verdictHead: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: space.md,
  },
  verdictHeadText: {
    flex: 1,
    alignItems: 'flex-start',
    gap: space.sm,
  },
  errorBox: {
    padding: space.md,
    borderRadius: radius.md,
  },
  metrics: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    rowGap: space.md,
  },
  metric: {
    flexBasis: '50%',
    gap: 1,
  },
  metricValue: {
    fontVariant: ['tabular-nums'],
  },
  docsRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    alignItems: 'center',
    gap: space.xs,
  },
  signals: {
    paddingTop: space.xs,
  },
});
