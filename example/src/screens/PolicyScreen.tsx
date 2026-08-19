/**
 * Build a policy, evaluate it, read the decision.
 *
 * This screen exists because the policy engine is the part of the toolkit most
 * likely to be misused. `evaluate()` returns a decision and does nothing else —
 * it does not block, terminate, or show UI — and the fastest way to make that
 * concrete is to let a reader flip the toggles a payments flow would use and see
 * a verdict with its evidence attached.
 *
 * `minimumConfidence` is given prominence for the same reason: it is the
 * practical false-positive control. Requiring corroborated high-confidence
 * evidence before blocking a payment is the difference between a policy that
 * ships and one that gets switched off after the first support ticket.
 */

import { useCallback, useState } from 'react';
import { StyleSheet, View } from 'react-native';
import {
  SecurityToolkit,
  type PolicyDecision,
  type RiskLevel,
  type SecurityPolicy,
  type SecurityReport,
} from 'react-native-security-toolkit';
import { useTheme } from '../theme/theme';
import { radius, space } from '../theme/tokens';
import { POLICY_REASONS, RISK_LEVELS } from '../security/catalog';
import { formatScore, formatTime } from '../security/derive';
import { fireAndForget } from '../utils/async';
import { Card, Divider, SectionHeader } from '../components/Card';
import {
  Note,
  Paragraph,
  PrimaryButton,
  Segmented,
  ToggleRow,
  type SegmentOption,
} from '../components/Controls';
import { Chip } from '../components/Pills';
import { Screen } from '../components/Screen';
import { Body, BodyStrong, Caption, Label, Mono, Title } from '../components/Typography';
import {
  AlertTriangleIcon,
  CheckCircleIcon,
  InfoIcon,
  PlayIcon,
  ShieldCheckIcon,
  ShieldOffIcon,
} from '../icons';

type Confidence = 'low' | 'medium' | 'high';
type RiskGate = RiskLevel | 'off';

interface Draft {
  readonly blockOnRoot: boolean;
  readonly blockOnJailbreak: boolean;
  readonly blockOnDebugger: boolean;
  readonly blockOnHooking: boolean;
  readonly blockOnIntegrityFailure: boolean;
  readonly requireSecureHardware: boolean;
  readonly requireStrongBiometrics: boolean;
  readonly minimumRiskLevel: RiskGate;
  readonly minimumConfidence: Confidence;
}

/**
 * The starting point is a payments-grade policy, minus the two capability
 * requirements that would deny on a great many ordinary handsets.
 */
const INITIAL: Draft = {
  blockOnRoot: true,
  blockOnJailbreak: true,
  blockOnDebugger: false,
  blockOnHooking: true,
  blockOnIntegrityFailure: true,
  requireSecureHardware: false,
  requireStrongBiometrics: false,
  minimumRiskLevel: 'high',
  minimumConfidence: 'medium',
};

export function PolicyScreen({ report }: { readonly report: SecurityReport }) {
  const { palette } = useTheme();
  const [draft, setDraft] = useState<Draft>(INITIAL);
  const [decision, setDecision] = useState<PolicyDecision | undefined>(undefined);
  const [busy, setBusy] = useState(false);

  const set = useCallback(<K extends keyof Draft>(key: K, value: Draft[K]) => {
    setDraft((current) => ({ ...current, [key]: value }));
    // A decision made under the previous policy would be misleading next to the
    // new toggles, so it is dropped rather than left on screen.
    setDecision(undefined);
  }, []);

  const evaluate = useCallback(async () => {
    setBusy(true);
    try {
      const result = await SecurityToolkit.evaluate(toPolicy(draft));
      console.log('[rnsec] decision', JSON.stringify(result));
      setDecision(result);
    } finally {
      setBusy(false);
    }
  }, [draft]);

  const riskOptions: readonly SegmentOption<RiskGate>[] = [
    { value: 'off', label: 'Off' },
    { value: 'medium', label: 'Medium' },
    { value: 'high', label: 'High' },
    { value: 'critical', label: 'Critical' },
  ];

  const confidenceOptions: readonly SegmentOption<Confidence>[] = [
    { value: 'low', label: 'Low' },
    { value: 'medium', label: 'Medium' },
    { value: 'high', label: 'High' },
  ];

  return (
    <Screen
      kicker="Policy engine"
      title="Evaluate a policy"
      subtitle="The toolkit returns a decision. Enforcement stays with your app."
    >
      <Card>
        <Paragraph>
          A policy is data, not behaviour. Nothing on this screen can block a user, end a session or
          terminate the process — evaluating returns a decision and its evidence, and what to do
          about a denial is the application's call.
        </Paragraph>
        <Note icon={InfoIcon}>
          {`Current posture: risk ${formatScore(report.risk.score)}/100 (${RISK_LEVELS[report.risk.level].label}). A policy is evaluated against a fresh aggregate run.`}
        </Note>
      </Card>

      <SectionHeader title="Block on" hint="Each toggle maps to one field of SecurityPolicy." />
      <Card style={styles.toggles}>
        <ToggleRow
          title="Root indicators"
          description="Android. Denies when the root check reports indicators at or above the confidence floor."
          value={draft.blockOnRoot}
          onChange={(next) => set('blockOnRoot', next)}
        />
        <Divider />
        <ToggleRow
          title="Jailbreak indicators"
          description="iOS. Same rule as root, on the other platform."
          value={draft.blockOnJailbreak}
          onChange={(next) => set('blockOnJailbreak', next)}
        />
        <Divider />
        <ToggleRow
          title="Hooking indicators"
          description="Instrumentation frameworks in the process. Strong reason to gate sensitive work."
          value={draft.blockOnHooking}
          onChange={(next) => set('blockOnHooking', next)}
        />
        <Divider />
        <ToggleRow
          title="Integrity mismatch"
          description="Signing certificate, installer or bundle identity not the ones you declared."
          value={draft.blockOnIntegrityFailure}
          onChange={(next) => set('blockOnIntegrityFailure', next)}
        />
        <Divider />
        <ToggleRow
          title="Debugger attached"
          description="Off by default here: a debugger is a development tool, and this fires on every debug run."
          value={draft.blockOnDebugger}
          onChange={(next) => set('blockOnDebugger', next)}
        />
      </Card>

      <SectionHeader title="Require" hint="Capability requirements, not threat detections." />
      <Card style={styles.toggles}>
        <ToggleRow
          title="Hardware-backed keys"
          description="Denies where the platform cannot back this app's keys in secure hardware."
          value={draft.requireSecureHardware}
          onChange={(next) => set('requireSecureHardware', next)}
        />
        <Divider />
        <ToggleRow
          title="Strong biometrics"
          description="Denies without usable Class 3 biometrics. Excludes users who deliberately use a PIN only."
          value={draft.requireStrongBiometrics}
          onChange={(next) => set('requireStrongBiometrics', next)}
        />
      </Card>

      <SectionHeader
        title="Risk gate"
        hint="Denies when the aggregate score reaches this band or above."
      />
      <Card>
        <Segmented
          options={riskOptions}
          value={draft.minimumRiskLevel}
          onChange={(next) => set('minimumRiskLevel', next)}
        />
        <Caption tone="muted">
          {draft.minimumRiskLevel === 'off'
            ? 'No score-based denial. Only the specific conditions above can deny.'
            : RISK_LEVELS[draft.minimumRiskLevel].advice}
        </Caption>
      </Card>

      <SectionHeader
        title="Confidence floor"
        hint="Detections weaker than this are ignored by the policy — they are still reported."
      />
      <Card>
        <Segmented
          options={confidenceOptions}
          value={draft.minimumConfidence}
          onChange={(next) => set('minimumConfidence', next)}
        />
        <Caption tone="muted">
          {draft.minimumConfidence === 'low'
            ? 'Every detection counts, including single weak indicators. Expect false positives.'
            : draft.minimumConfidence === 'medium'
              ? 'Ignores lone weak indicators. A sensible default for most flows.'
              : 'Only corroborated high-confidence evidence can deny. The strictest false-positive control.'}
        </Caption>
      </Card>

      <SectionHeader title="Policy" hint="What the toggles above compile to." />
      <Card tint={palette.surfaceRaised}>
        <Mono tone="muted">{JSON.stringify(toPolicy(draft), null, 2)}</Mono>
      </Card>

      <View style={styles.action}>
        <PrimaryButton
          label="Evaluate policy"
          icon={PlayIcon}
          onPress={fireAndForget(evaluate)}
          busy={busy}
        />
      </View>

      {decision === undefined ? null : <Decision decision={decision} />}
    </Screen>
  );
}

function Decision({ decision }: { readonly decision: PolicyDecision }) {
  const { palette } = useTheme();
  const allowed = decision.allowed;
  const color = allowed ? palette.status.secure : palette.status.detected;
  const Glyph = allowed ? ShieldCheckIcon : ShieldOffIcon;

  return (
    <>
      <SectionHeader title="Decision" hint={`Evaluated at ${formatTime(decision.evaluatedAt)}.`} />
      <Card accent={color} tint={allowed ? palette.statusSoft.secure : palette.statusSoft.detected}>
        <View style={styles.decisionHead}>
          <Glyph size={26} color={color} strokeWidth={1.9} />
          <View style={styles.decisionText}>
            <Title color={color}>{allowed ? 'Allowed' : 'Denied'}</Title>
            <Caption tone="muted">
              {allowed
                ? 'No policy condition matched. This is a decision about one moment, not a clean bill of health.'
                : 'One or more conditions matched. Your app decides what happens next.'}
            </Caption>
          </View>
        </View>

        <Divider />

        <View style={styles.decisionMeta}>
          <Chip label={`risk ${formatScore(decision.risk.score)}/100`} />
          <Chip
            label={RISK_LEVELS[decision.risk.level].label}
            color={palette.risk[decision.risk.level]}
          />
          <Chip label={decision.risk.methodologyVersion} />
        </View>

        {decision.reasons.length === 0 ? (
          <Note icon={CheckCircleIcon} tone={color}>
            No reasons returned. Nothing in this policy was triggered by the current posture.
          </Note>
        ) : (
          <View style={styles.reasons}>
            {decision.reasons.map((reason) => (
              <View key={reason.code} style={[styles.reason, { borderColor: palette.border }]}>
                <View style={styles.reasonHead}>
                  <AlertTriangleIcon size={14} color={color} strokeWidth={2} />
                  <BodyStrong color={color}>{POLICY_REASONS[reason.code]}</BodyStrong>
                  <Label tone="faint">{reason.code}</Label>
                </View>
                <Body tone="muted">{reason.message}</Body>
                {reason.signalIds.length === 0 ? null : (
                  <View style={styles.reasonSignals}>
                    {reason.signalIds.map((id) => (
                      <Chip key={id} label={id} />
                    ))}
                  </View>
                )}
              </View>
            ))}
          </View>
        )}

        <Note icon={InfoIcon}>
          Sensible responses to a denial: gate the sensitive operation, require re-authentication,
          log a security event, or degrade the feature. Terminating the app is rarely one of them.
        </Note>
      </Card>
    </>
  );
}

/**
 * Compiles the draft into a `SecurityPolicy`.
 *
 * Only fields the reader actually set are included, so the JSON preview doubles
 * as something that can be pasted into an application — an empty policy allows
 * everything, and `false` is not the same as absent when someone is reading the
 * output to learn the API.
 */
function toPolicy(draft: Draft): SecurityPolicy {
  return {
    ...(draft.blockOnRoot ? { blockOnRoot: true } : {}),
    ...(draft.blockOnJailbreak ? { blockOnJailbreak: true } : {}),
    ...(draft.blockOnDebugger ? { blockOnDebugger: true } : {}),
    ...(draft.blockOnHooking ? { blockOnHooking: true } : {}),
    ...(draft.blockOnIntegrityFailure ? { blockOnIntegrityFailure: true } : {}),
    ...(draft.requireSecureHardware ? { requireSecureHardware: true } : {}),
    ...(draft.requireStrongBiometrics ? { requireStrongBiometrics: true } : {}),
    ...(draft.minimumRiskLevel === 'off' ? {} : { minimumRiskLevel: draft.minimumRiskLevel }),
    minimumConfidence: draft.minimumConfidence,
  };
}

const styles = StyleSheet.create({
  toggles: {
    gap: space.md,
  },
  action: {
    marginTop: space.xl,
  },
  decisionHead: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: space.md,
  },
  decisionText: {
    flex: 1,
    gap: 2,
  },
  decisionMeta: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: space.xs,
  },
  reasons: {
    gap: space.sm,
  },
  reason: {
    borderWidth: StyleSheet.hairlineWidth,
    borderRadius: radius.md,
    padding: space.md,
    gap: space.xs,
  },
  reasonHead: {
    flexDirection: 'row',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: space.sm,
  },
  reasonSignals: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: space.xs,
    marginTop: 2,
  },
});
