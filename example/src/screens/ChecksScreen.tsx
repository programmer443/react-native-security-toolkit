/**
 * Every check on this platform, filterable by status.
 *
 * The filter counts are part of the information: "6 unavailable" on Android is
 * not a failure, it is the iOS half of the toolkit correctly declining to
 * pretend. Grouping by status rather than alphabetically puts whatever needs
 * attention at the top, which is the order someone triaging actually wants.
 */

import { useMemo, useState } from 'react';
import { StyleSheet, View } from 'react-native';
import type { CheckId, SecurityReport, SecurityStatus } from 'react-native-security-toolkit';
import { useTheme } from '../theme/theme';
import { space } from '../theme/tokens';
import { STATUS } from '../security/catalog';
import { bySeverity, orderedChecks, summarise } from '../security/derive';
import { useSecurity } from '../security/SecurityProvider';
import { fireAndForget } from '../utils/async';
import { Card, Divider, SectionHeader } from '../components/Card';
import { CheckRow } from '../components/CheckRow';
import { Note, Segmented, type SegmentOption } from '../components/Controls';
import { Screen } from '../components/Screen';
import { Caption } from '../components/Typography';
import { InfoIcon, MinusCircleIcon } from '../icons';

type Filter = 'all' | 'attention' | 'clear' | 'unavailable';

export function ChecksScreen({
  report,
  onOpenCheck,
}: {
  readonly report: SecurityReport;
  readonly onOpenCheck: (id: CheckId) => void;
}) {
  const { refresh, refreshing } = useSecurity();
  const [filter, setFilter] = useState<Filter>('all');

  const checks = useMemo(() => [...orderedChecks(report)].sort(bySeverity), [report]);
  const summary = summarise(report);

  const visible = checks.filter((check) => matches(filter, check.status));
  const options: readonly SegmentOption<Filter>[] = [
    { value: 'all', label: 'All', count: checks.length },
    {
      value: 'attention',
      label: 'Attention',
      count: summary.detected + summary.inconclusive,
    },
    {
      value: 'clear',
      label: 'Clear',
      count: checks.filter((check) => check.status === 'secure').length,
    },
    { value: 'unavailable', label: 'N/A', count: summary.unavailable },
  ];

  return (
    <Screen
      kicker={`${checks.length} checks · ${report.platform}`}
      title="Checks"
      subtitle="Each check aggregates its own signals into one verdict."
      refreshing={refreshing}
      onRefresh={fireAndForget(refresh)}
    >
      <Segmented options={options} value={filter} onChange={setFilter} />

      {visible.length === 0 ? (
        <Card style={styles.empty}>
          <Note icon={MinusCircleIcon}>Nothing in this group on this platform.</Note>
        </Card>
      ) : (
        <>
          <SectionHeader
            title={filter === 'all' ? 'Ordered by attention' : STATUS[groupStatus(filter)].label}
            hint={
              filter === 'unavailable'
                ? 'A check that does not exist on this platform is reported as unavailable, never as a silent pass.'
                : undefined
            }
          />
          <Card>
            {visible.map((result, index) => (
              <View key={result.id}>
                {index === 0 ? null : <Divider />}
                <CheckRow result={result} onPress={() => onOpenCheck(result.id)} />
              </View>
            ))}
          </Card>
        </>
      )}

      <SectionHeader title="Reading a verdict" />
      <Card style={styles.legend}>
        {(['detected', 'unknown', 'secure', 'unavailable', 'error'] as const).map((status) => (
          <LegendRow key={status} status={status} />
        ))}
        <Note icon={InfoIcon}>
          Inconclusive and clear are different answers. A probe that could not run has demonstrated
          nothing, and the toolkit will not report it as safe.
        </Note>
      </Card>

      <Caption tone="faint" style={styles.footer}>
        {`Signals across all checks: ${summary.signals.fired} fired · ${summary.signals.inconclusive} inconclusive · ${summary.signals.total} total.`}
      </Caption>
    </Screen>
  );
}

function LegendRow({ status }: { readonly status: SecurityStatus }) {
  const { palette } = useTheme();
  const meta = STATUS[status];
  const Glyph = meta.icon;
  return (
    <View style={styles.legendRow}>
      <Glyph size={15} color={palette.status[status]} strokeWidth={2} />
      <Caption tone="muted" style={styles.legendText}>
        <Caption color={palette.status[status]}>{`${meta.label} — `}</Caption>
        {meta.explain('threat')}
      </Caption>
    </View>
  );
}

function matches(filter: Filter, status: SecurityStatus): boolean {
  switch (filter) {
    case 'all':
      return true;
    case 'attention':
      return status === 'detected' || status === 'unknown' || status === 'error';
    case 'clear':
      return status === 'secure';
    case 'unavailable':
      return status === 'unavailable';
  }
}

function groupStatus(filter: Exclude<Filter, 'all'>): SecurityStatus {
  switch (filter) {
    case 'attention':
      return 'detected';
    case 'clear':
      return 'secure';
    case 'unavailable':
      return 'unavailable';
  }
}

const styles = StyleSheet.create({
  empty: {
    marginTop: space.lg,
  },
  legend: {
    gap: space.md,
  },
  legendRow: {
    flexDirection: 'row',
    gap: space.sm,
  },
  legendText: {
    flex: 1,
  },
  footer: {
    marginTop: space.lg,
  },
});
