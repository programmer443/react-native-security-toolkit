/**
 * The two screens that are not a report: still working, and not linked.
 *
 * The distinction they draw is the one the toolkit itself is careful about. A
 * missing native module is a **build problem**, not a device verdict — so this
 * screen says so plainly and lists what to check, rather than rendering an
 * alarming empty dashboard that looks like a security finding.
 */

import { StyleSheet, View } from 'react-native';
import LottieView from 'lottie-react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTheme } from '../theme/theme';
import { space } from '../theme/tokens';
import { DEFENCE_IN_DEPTH_NOTE } from '../security/catalog';
import type { SecurityUnavailable } from '../security/SecurityProvider';
import { Card } from '../components/Card';
import { Note, Paragraph, PrimaryButton } from '../components/Controls';
import { Chip } from '../components/Pills';
import { Body, Caption, Label, Mono, Title, textStyles } from '../components/Typography';
import { InfoIcon, RefreshIcon, ShieldOffIcon } from '../icons';

const ANIMATIONS = {
  checkingLight: require('../animations/checking-light.json'),
  checkingDark: require('../animations/checking-dark.json'),
  unavailable: require('../animations/unavailable.json'),
};

export function LoadingScreen() {
  const { palette, isDark } = useTheme();
  return (
    <View style={[styles.centre, { backgroundColor: palette.background }]}>
      <LottieView
        source={isDark ? ANIMATIONS.checkingDark : ANIMATIONS.checkingLight}
        autoPlay
        loop
        style={styles.hero}
      />
      <Title style={textStyles.center}>Reading device posture</Title>
      <Body tone="muted" style={[textStyles.center, styles.narrow]}>
        Running every check this platform implements in a single bridge crossing.
      </Body>
      <Caption tone="faint" style={[textStyles.center, styles.narrow]}>
        {DEFENCE_IN_DEPTH_NOTE}
      </Caption>
    </View>
  );
}

export function UnavailableScreen({
  error,
  onRetry,
}: {
  readonly error: SecurityUnavailable;
  readonly onRetry: () => void;
}) {
  const { palette } = useTheme();
  const insets = useSafeAreaInsets();
  const diagnosis = diagnose(error.code);

  return (
    <View
      style={[
        styles.centre,
        { backgroundColor: palette.background, paddingTop: insets.top + space.xl },
      ]}
    >
      <LottieView source={ANIMATIONS.unavailable} autoPlay loop style={styles.hero} />
      <Title style={textStyles.center}>{diagnosis.title}</Title>
      <Body tone="muted" style={[textStyles.center, styles.narrow]}>
        {diagnosis.lead}
      </Body>

      <Card style={styles.card}>
        <View style={styles.cardHead}>
          <ShieldOffIcon size={18} color={palette.status.error} />
          <Label tone="faint">Error</Label>
          <Chip label={error.code} color={palette.status.error} tint={palette.statusSoft.error} />
        </View>
        <Mono tone="muted">{error.message}</Mono>
      </Card>

      <Card style={styles.card}>
        <Label tone="faint">What to check</Label>
        {diagnosis.hints.map((hint) => (
          <Paragraph key={hint}>{hint}</Paragraph>
        ))}
        <Note icon={InfoIcon}>{diagnosis.note}</Note>
      </Card>

      <View style={styles.action}>
        <PrimaryButton label="Try again" onPress={onRetry} icon={RefreshIcon} />
      </View>
    </View>
  );
}

interface Diagnosis {
  readonly title: string;
  readonly lead: string;
  readonly hints: readonly string[];
  readonly note: string;
}

/**
 * Turns an error code into an accurate explanation.
 *
 * Worth doing properly rather than showing one generic failure screen: these
 * three codes mean genuinely different things, and telling someone to rebuild
 * when the engine answered but was slow sends them off in the wrong direction.
 * A timeout in particular is not evidence that anything is wrong with the
 * device — the checks that did run are simply discarded, because a partial
 * report scored as if it were complete would understate risk.
 */
function diagnose(code: string): Diagnosis {
  switch (code) {
    case 'NATIVE_TIMEOUT':
      return {
        title: 'Engine did not answer in time',
        lead: 'The native engine is linked but did not finish within the configured timeout, so the aggregate run was abandoned.',
        hints: [
          'Debug builds on emulators are several times slower than release builds on hardware. Filesystem probes and generating a Keystore key are the usual cost.',
          'Raise the budget with SecurityToolkit.configure({ nativeTimeoutMs }) — this example already uses 20 s for that reason.',
          'Switch off checks an app does not need with disabledChecks; they report unavailable with a disabled-by-config reason rather than a silent pass.',
        ],
        note: 'A timeout is a budget being exceeded, not a finding about this device. Nothing here says the device is compromised.',
      };
    case 'INVALID_NATIVE_PAYLOAD':
      return {
        title: 'Unexpected response from the engine',
        lead: 'The native engine answered, but not in a shape this build of the JavaScript API recognises.',
        hints: [
          'This usually means the JavaScript package and the native engine are from different versions. Rebuild both from the same checkout.',
          'Clear stale build artefacts, then reinstall the app rather than reloading JavaScript.',
        ],
        note: 'The toolkit validates every native payload rather than trusting it, which is why this surfaces as an error instead of a malformed report.',
      };
    default:
      return {
        title: 'Native engine not linked',
        lead: 'The JavaScript API loaded, but the native security engine did not answer. This is a build problem — not a finding about this device.',
        hints: [
          'Rebuild the app after installing the package — a JavaScript reload is not enough for a new native module.',
          'On iOS, run pod install in example/ios, then rebuild from Xcode or the CLI.',
          'On Android, sync Gradle so autolinking picks the module up, then reinstall the app.',
        ],
        note: 'The New Architecture generates the bridge at build time, so stale build artefacts produce exactly this error.',
      };
  }
}

const styles = StyleSheet.create({
  centre: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    padding: space.xl,
    gap: space.md,
  },
  hero: {
    width: 132,
    height: 132,
  },
  narrow: {
    maxWidth: 340,
  },
  card: {
    alignSelf: 'stretch',
    marginTop: space.sm,
  },
  cardHead: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: space.sm,
  },
  action: {
    alignSelf: 'stretch',
    marginTop: space.sm,
  },
});
