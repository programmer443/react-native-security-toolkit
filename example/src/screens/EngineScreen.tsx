/**
 * The engine, the configuration, and the one control that changes device state.
 *
 * Screen protection is the toolkit's only mutating API, so it gets a real
 * control here rather than a description — and the platform difference is stated
 * next to the switch instead of in a footnote, because on iOS the switch cannot
 * do what an Android reader will assume it does.
 */

import { useCallback, useState } from 'react';
import { Platform, StyleSheet, View } from 'react-native';
import {
  ScreenSecurity,
  SecurityToolkit,
  type NativeEngineInfo,
  type SecurityReport,
} from 'react-native-security-toolkit';
import { useTheme } from '../theme/theme';
import { space } from '../theme/tokens';
import { CHECKS, DEFENCE_IN_DEPTH_NOTE } from '../security/catalog';
import { formatDuration, formatTime } from '../security/derive';
import { useSecurity } from '../security/SecurityProvider';
import { fireAndForget } from '../utils/async';
import { Card, Divider, KeyValue, SectionHeader } from '../components/Card';
import { Note, Paragraph, ToggleRow } from '../components/Controls';
import { Chip, IconBadge, StatusPill } from '../components/Pills';
import { Screen } from '../components/Screen';
import { Caption, Mono } from '../components/Typography';
import {
  AlertTriangleIcon,
  CheckCircleIcon,
  CpuIcon,
  EyeIcon,
  EyeOffIcon,
  InfoIcon,
} from '../icons';

export function EngineScreen({
  engine,
  report,
}: {
  readonly engine: NativeEngineInfo;
  readonly report: SecurityReport;
}) {
  const { palette } = useTheme();
  const { developmentMode, setDevelopmentMode, refresh, refreshing } = useSecurity();
  const [protectionOn, setProtectionOn] = useState(false);
  const [protectionApplied, setProtectionApplied] = useState<boolean | undefined>(undefined);

  const configuration = SecurityToolkit.getConfiguration();
  const screenCheck = report.checks.screen;

  const toggleProtection = useCallback(async (next: boolean) => {
    setProtectionOn(next);
    const applied = next
      ? await ScreenSecurity.enableProtection()
      : await ScreenSecurity.disableProtection();
    console.log('[rnsec] screen protection', next, applied);
    setProtectionApplied(applied);
  }, []);

  return (
    <Screen
      kicker="Native engine"
      title="Engine & configuration"
      subtitle={`${engine.platform} ${engine.osVersion} · engine ${engine.engineVersion}`}
      refreshing={refreshing}
      onRefresh={fireAndForget(refresh)}
    >
      <Card>
        <View style={styles.head}>
          <IconBadge
            icon={CpuIcon}
            color={palette.status.secure}
            tint={palette.statusSoft.secure}
            size={44}
          />
          <View style={styles.headText}>
            <Chip
              label="native module linked"
              icon={CheckCircleIcon}
              color={palette.status.secure}
              tint={palette.statusSoft.secure}
            />
            <Caption tone="muted">
              A successful engine call proves the TypeScript API, the generated bridge and the
              native engine are wired together.
            </Caption>
          </View>
        </View>
        <Divider />
        <KeyValue label="Platform" value={engine.platform} />
        <KeyValue label="OS version" value={engine.osVersion} />
        <KeyValue label="Engine version" value={engine.engineVersion} />
        <KeyValue label="Aggregate run" value={formatDuration(report.durationMs)} />
        <KeyValue label="Last run" value={formatTime(report.checkedAt)} />
      </Card>

      <SectionHeader
        title={`Implemented checks · ${engine.supportedChecks.length}`}
        hint="Reported by the engine itself. Anything absent here is absent from the report."
      />
      <Card>
        <View style={styles.chips}>
          {engine.supportedChecks.length === 0 ? (
            <Caption tone="muted">This engine reports no checks.</Caption>
          ) : (
            engine.supportedChecks.map((id) => <Chip key={id} label={label(id)} />)
          )}
        </View>
      </Card>

      <SectionHeader
        title="Screen protection"
        hint="The only API here that changes device state."
      />
      <Card>
        <ToggleRow
          title="Capture protection"
          description={
            Platform.OS === 'android'
              ? 'FLAG_SECURE. The platform blocks screenshots and recordings of this window.'
              : 'iOS has no public API to prevent a screenshot. Detection only — this cannot stop a capture.'
          }
          value={protectionOn}
          onChange={fireAndForget(toggleProtection)}
        />
        {protectionApplied === undefined ? null : (
          <Note icon={protectionApplied ? EyeOffIcon : EyeIcon}>
            {protectionApplied
              ? 'The change reached a live window.'
              : 'The intent was recorded but no live window took it — expected during a cold start, or where the platform cannot honour it.'}
          </Note>
        )}
        {screenCheck === undefined ? null : (
          <View style={styles.statusRow}>
            <Caption tone="muted">Last reported by the check</Caption>
            <StatusPill status={screenCheck.status} size="sm" />
          </View>
        )}
        <Note icon={AlertTriangleIcon} tone={palette.status.unknown}>
          {CHECKS.screen.caveat}
        </Note>
      </Card>

      <SectionHeader title="Development mode" hint="Changes interpretation, never findings." />
      <Card>
        <ToggleRow
          title="Treat this as a development build"
          description="Debugger, emulator and simulator signals stop contributing to the risk score. The check results underneath are identical."
          value={developmentMode}
          onChange={setDevelopmentMode}
        />
        <Note icon={InfoIcon}>
          Toggling this re-scores the existing results with the public risk engine rather than
          re-running the native checks — which is the point: nothing about the device changed.
        </Note>
      </Card>

      <SectionHeader title="Resolved configuration" hint="SecurityToolkit.getConfiguration()." />
      <Card>
        <KeyValue label="developmentMode" value={String(configuration.developmentMode)} />
        <KeyValue label="nativeTimeoutMs" value={String(configuration.nativeTimeoutMs)} />
        <KeyValue
          label="disabledChecks"
          value={
            configuration.disabledChecks.length === 0
              ? 'none'
              : configuration.disabledChecks.join(', ')
          }
        />
        <Divider />
        <Caption tone="faint">integrity expectations</Caption>
        <Mono tone="muted">{JSON.stringify(configuration.integrity, null, 2)}</Mono>
        <Note icon={InfoIcon}>
          Three of the four integrity signals report inconclusive until the app declares what it
          expects. The example declares its own identity; a shipping app would use its published
          signing fingerprint.
        </Note>
      </Card>

      <SectionHeader title="About this example" />
      <Card>
        <Paragraph>
          Every number on these screens comes from one aggregate run of the native engine. Nothing
          is simulated, and no result is invented where a platform cannot answer.
        </Paragraph>
        <Paragraph>
          There is no telemetry, no analytics and no network request anywhere in the toolkit or this
          app.
        </Paragraph>
        <Note icon={InfoIcon}>{DEFENCE_IN_DEPTH_NOTE}</Note>
      </Card>
    </Screen>
  );
}

/**
 * Engine check ids are strings rather than a closed union — a newer engine may
 * report one this build does not know — so an unknown id is shown verbatim
 * instead of being dropped.
 */
function label(id: string): string {
  return id in CHECKS ? CHECKS[id as keyof typeof CHECKS].title : id;
}

const styles = StyleSheet.create({
  head: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: space.md,
  },
  headText: {
    flex: 1,
    alignItems: 'flex-start',
    gap: space.xs,
  },
  chips: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: space.xs,
  },
  statusRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: space.sm,
  },
});
