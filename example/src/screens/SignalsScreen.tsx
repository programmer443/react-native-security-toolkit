/**
 * Every signal in the report, searchable.
 *
 * This is the screen for the person who wants to know what the toolkit actually
 * looked at. Signal identifiers are stable and published, so searching for
 * `RNSEC-ANDROID-ROOT-005` here and finding it in `docs/runtime/root-detection.md`
 * gives the same answer — that is the point of publishing them.
 *
 * The default filter is "fired" rather than "all". A hundred quiet signals are
 * exactly what a healthy device produces, and burying the four that fired inside
 * them would be a worse default than making "all" one tap away.
 */

import { useMemo, useState } from 'react';
import { StyleSheet, TextInput, View } from 'react-native';
import type { SecurityReport, SignalOutcome } from 'react-native-security-toolkit';
import { useTheme } from '../theme/theme';
import { radius, space } from '../theme/tokens';
import { CHECKS } from '../security/catalog';
import { allSignals, contributorIndex, tally } from '../security/derive';
import { useSecurity } from '../security/SecurityProvider';
import { fireAndForget } from '../utils/async';
import { Card, SectionHeader } from '../components/Card';
import { Note, Segmented, type SegmentOption } from '../components/Controls';
import { Screen } from '../components/Screen';
import { SignalRow } from '../components/SignalRow';
import { Caption } from '../components/Typography';
import { InfoIcon, SearchIcon } from '../icons';

type Filter = SignalOutcome | 'all';

export function SignalsScreen({ report }: { readonly report: SecurityReport }) {
  const { palette } = useTheme();
  const { refresh, refreshing } = useSecurity();
  const [filter, setFilter] = useState<Filter>('detected');
  const [query, setQuery] = useState('');

  const signals = useMemo(() => allSignals(report), [report]);
  const contributors = contributorIndex(report);
  const counts = tally(signals.map(({ signal }) => signal));

  const needle = query.trim().toLowerCase();
  const visible = signals.filter(({ signal, checkId }) => {
    if (filter !== 'all' && signal.outcome !== filter) {
      return false;
    }
    if (needle.length === 0) {
      return true;
    }
    return (
      signal.id.toLowerCase().includes(needle) ||
      signal.description.toLowerCase().includes(needle) ||
      CHECKS[checkId].title.toLowerCase().includes(needle)
    );
  });

  const options: readonly SegmentOption<Filter>[] = [
    { value: 'detected', label: 'Fired', count: counts.fired },
    { value: 'indeterminate', label: 'Unclear', count: counts.inconclusive },
    { value: 'not-detected', label: 'Clear', count: counts.clear },
    { value: 'all', label: 'All', count: counts.total },
  ];

  return (
    <Screen
      kicker={`${counts.total} signals · ${report.platform}`}
      title="Signal explorer"
      subtitle="Identifiers here match the ones documented per detector."
      refreshing={refreshing}
      onRefresh={fireAndForget(refresh)}
    >
      <View
        style={[styles.search, { backgroundColor: palette.surface, borderColor: palette.border }]}
      >
        <SearchIcon size={16} color={palette.textFaint} />
        <TextInput
          value={query}
          onChangeText={setQuery}
          placeholder="Search id, description or check"
          placeholderTextColor={palette.textFaint}
          style={[styles.input, { color: palette.text }]}
          autoCapitalize="characters"
          autoCorrect={false}
          returnKeyType="search"
          clearButtonMode="while-editing"
        />
      </View>

      <Segmented options={options} value={filter} onChange={setFilter} style={styles.filter} />

      {visible.length === 0 ? (
        <Card style={styles.empty}>
          <Note icon={InfoIcon}>
            {needle.length > 0
              ? 'No signal matches that search in this group.'
              : 'Nothing in this group. On a healthy device the fired group is empty, which is the outcome you want.'}
          </Note>
        </Card>
      ) : (
        <>
          <SectionHeader
            title={`${visible.length} shown`}
            hint="Tap a signal to see the detector's metadata."
          />
          <Card style={styles.list}>
            {visible.map(({ signal, checkId }, index) => {
              const contributor = contributors.get(signal.id);
              return (
                <SignalRow
                  key={`${checkId}-${signal.id}`}
                  signal={signal}
                  checkId={checkId}
                  first={index === 0}
                  contributor={contributor}
                />
              );
            })}
          </Card>
        </>
      )}

      <Caption tone="faint" style={styles.footer}>
        Points shown on a signal are its contribution to the risk score: base weight for that signal
        multiplied by its confidence, which is why two fired signals rarely cost the same.
      </Caption>
    </Screen>
  );
}

const styles = StyleSheet.create({
  search: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: space.sm,
    paddingHorizontal: space.md,
    borderRadius: radius.md,
    borderWidth: StyleSheet.hairlineWidth,
  },
  input: {
    flex: 1,
    paddingVertical: 11,
    fontSize: 14,
  },
  filter: {
    marginTop: space.sm,
  },
  empty: {
    marginTop: space.lg,
  },
  list: {
    paddingTop: space.xs,
  },
  footer: {
    marginTop: space.lg,
  },
});
