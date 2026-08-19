/**
 * Icon set for the example app.
 *
 * Hand-drawn rather than pulled from an icon font, for two reasons. First, half
 * of these concepts — Zygisk indicators, code-signing integrity, hardware-backed
 * keys — have no icon in a generic set, and a wrong icon is worse than none.
 * Second, an icon font would mean registering fonts in `Info.plist` and Gradle,
 * which is setup noise in a package example whose job is to demonstrate the
 * toolkit rather than an icon pipeline.
 *
 * All icons share a 24×24 grid, stroke-only geometry and a 1.7 stroke, so they
 * sit on a line of text at any size without one looking heavier than another.
 */

import type { ReactNode } from 'react';
import Svg, { Circle, G, Path, Rect } from 'react-native-svg';

export interface IconProps {
  readonly size?: number | undefined;
  readonly color: string;
  readonly strokeWidth?: number | undefined;
}

export type IconComponent = (props: IconProps) => ReactNode;

function Frame({
  size = 20,
  color,
  strokeWidth = 1.7,
  children,
}: IconProps & { readonly children: ReactNode }) {
  return (
    <Svg width={size} height={size} viewBox="0 0 24 24">
      <G
        fill="none"
        stroke={color}
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        {children}
      </G>
    </Svg>
  );
}

/** Filled dot, used for the "i" of an info glyph and for confidence markers. */
function Dot({ color, cx, cy, r = 1.05 }: { color: string; cx: number; cy: number; r?: number }) {
  return <Circle cx={cx} cy={cy} r={r} fill={color} stroke="none" />;
}

const SHIELD = 'M12 2.7 20 5.5v6.2c0 4.6-3.2 8.1-8 9.6-4.8-1.5-8-5-8-9.6V5.5z';

// ── Product marks ─────────────────────────────────────────────────────────────

export const ShieldCheckIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Path d={SHIELD} />
    <Path d="m8.7 11.9 2.4 2.4 4.2-4.6" />
  </Frame>
);

export const ShieldAlertIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Path d={SHIELD} />
    <Path d="M12 8v4.2" />
    <Dot color={p.color} cx={12} cy={15.4} />
  </Frame>
);

export const ShieldOffIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Path d={SHIELD} />
    <Path d="M4.2 3.4 19.8 20.6" />
  </Frame>
);

// ── Tab bar ───────────────────────────────────────────────────────────────────

export const GaugeIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Path d="M3.6 17a8.9 8.9 0 1 1 16.8 0" />
    <Path d="M12 13.6 16.2 9" />
    <Dot color={p.color} cx={12} cy={17} r={1.3} />
  </Frame>
);

export const LayersIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Path d="m12 2.8 8.4 4.6-8.4 4.6-8.4-4.6z" />
    <Path d="m3.6 12 8.4 4.6 8.4-4.6" />
    <Path d="m3.6 16.6 8.4 4.6 8.4-4.6" />
  </Frame>
);

export const PulseIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Path d="M2.6 12h3.9l2.6-7.2 4.2 14.4 2.6-7.2h5.5" />
  </Frame>
);

export const SlidersIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Path d="M6 3.4v5.2M6 13.4v7.2" />
    <Circle cx={6} cy={11} r={2.2} />
    <Path d="M12 3.4v9.2M12 17.4v3.2" />
    <Circle cx={12} cy={15} r={2.2} />
    <Path d="M18 3.4v1.2M18 9.4v11.2" />
    <Circle cx={18} cy={7} r={2.2} />
  </Frame>
);

export const CpuIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Rect x={6} y={6} width={12} height={12} rx={2.4} />
    <Rect x={9.6} y={9.6} width={4.8} height={4.8} rx={1.2} />
    <Path d="M9.6 3v3M14.4 3v3M9.6 18v3M14.4 18v3M3 9.6h3M3 14.4h3M18 9.6h3M18 14.4h3" />
  </Frame>
);

// ── Per-check marks ───────────────────────────────────────────────────────────

/** Root: a shell prompt. What root access ultimately is. */
export const TerminalIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Rect x={2.8} y={4} width={18.4} height={16} rx={2.6} />
    <Path d="m7.4 10 2.4 2-2.4 2" />
    <Path d="M12.6 14h4.2" />
  </Frame>
);

/** Jailbreak: a lock whose shackle has been sprung. */
export const UnlockIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Rect x={4.4} y={10.6} width={15.2} height={10.4} rx={2.4} />
    <Path d="M8.2 10.6V7.4A3.8 3.8 0 0 1 15.4 5.8" />
    <Path d="M12 14.6v2.6" />
  </Frame>
);

export const BugIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Path d="M8.4 8.4h7.2a3.8 3.8 0 0 1 3.8 3.8v1a5.2 5.2 0 0 1-5.2 5.2h-4.2A5.2 5.2 0 0 1 4.6 13.2v-1a3.8 3.8 0 0 1 3.8-3.8z" />
    <Path d="m9.2 8.4-2-3.2M14.8 8.4l2-3.2" />
    <Path d="M4.6 12.4H2.2M21.8 12.4h-2.4M5 17.8l-2 1.6M19 17.8l2 1.6" />
  </Frame>
);

export const MonitorIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Rect x={2.4} y={3.8} width={19.2} height={12.6} rx={2.4} />
    <Path d="M12 16.4v3.8M8.6 20.2h6.8" />
  </Frame>
);

export const SmartphoneIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Rect x={6.6} y={2.4} width={10.8} height={19.2} rx={2.8} />
    <Path d="M10.8 18.8h2.4" />
  </Frame>
);

/** Hooking: something taking aim at the process from outside it. */
export const CrosshairIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Circle cx={12} cy={12} r={7.6} />
    <Circle cx={12} cy={12} r={2.2} />
    <Path d="M12 1.8v3M12 19.2v3M1.8 12h3M19.2 12h3" />
  </Frame>
);

/** Integrity: a seal with a check, i.e. this build is the one that was signed. */
export const SealCheckIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Circle cx={12} cy={10.2} r={6.6} />
    <Path d="m9.2 10.2 2.1 2.1 3.6-3.9" />
    <Path d="m8.4 16-1.2 5.2 4.8-2.3 4.8 2.3L15.6 16" />
  </Frame>
);

export const FingerprintIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Path d="M3.6 12.6a8.4 8.4 0 0 1 16.8 0" />
    <Path d="M6.6 16.2v-3.6a5.4 5.4 0 0 1 10.8 0v3.6" />
    <Path d="M9.6 19v-6.4a2.4 2.4 0 0 1 4.8 0V19" />
    <Path d="M6.6 19.4v.8M17.4 19.4v.8" />
  </Frame>
);

export const GlobeIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Circle cx={12} cy={12} r={8.6} />
    <Path d="M12 3.4c2.4 2.4 3.8 5.4 3.8 8.6S14.4 18.2 12 20.6c-2.4-2.4-3.8-5.4-3.8-8.6S9.6 5.8 12 3.4z" />
    <Path d="M3.5 12h17" />
  </Frame>
);

export const EyeOffIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Path d="M3.2 3.2 20.8 20.8" />
    <Path d="M10.5 10.6a2.1 2.1 0 0 0 2.9 2.9" />
    <Path d="M6.4 6.8C4.5 8.1 3.1 9.9 2.4 12c1.4 3.8 5.2 6.4 9.6 6.4 1.6 0 3.2-.4 4.6-1" />
    <Path d="M9.8 5.8A9.9 9.9 0 0 1 12 5.6c4.4 0 8.2 2.6 9.6 6.4-.5 1.4-1.4 2.6-2.5 3.7" />
  </Frame>
);

export const EyeIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Path d="M2.4 12C3.8 8.2 7.6 5.6 12 5.6s8.2 2.6 9.6 6.4c-1.4 3.8-5.2 6.4-9.6 6.4S3.8 15.8 2.4 12z" />
    <Circle cx={12} cy={12} r={2.7} />
  </Frame>
);

// ── Interface glyphs ──────────────────────────────────────────────────────────

export const RefreshIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Path d="M20.6 12a8.6 8.6 0 1 1-2.7-6.2" />
    <Path d="M20.9 3.6v4.6h-4.6" />
  </Frame>
);

export const ChevronRightIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Path d="m9.6 5.8 6.2 6.2-6.2 6.2" />
  </Frame>
);

export const ChevronDownIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Path d="m5.8 9.4 6.2 6.2 6.2-6.2" />
  </Frame>
);

export const ArrowLeftIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Path d="M19.4 12H4.6" />
    <Path d="m10.8 5.8-6.2 6.2 6.2 6.2" />
  </Frame>
);

export const InfoIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Circle cx={12} cy={12} r={9} />
    <Path d="M12 11.2V16.4" />
    <Dot color={p.color} cx={12} cy={8.1} />
  </Frame>
);

export const AlertTriangleIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Path d="M12 3.4 22 20.2H2z" />
    <Path d="M12 9.4v4.4" />
    <Dot color={p.color} cx={12} cy={16.9} />
  </Frame>
);

export const CheckCircleIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Circle cx={12} cy={12} r={9} />
    <Path d="m8 12.2 2.7 2.7L16.4 9" />
  </Frame>
);

export const XCircleIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Circle cx={12} cy={12} r={9} />
    <Path d="m9 9 6 6M15 9l-6 6" />
  </Frame>
);

export const HelpCircleIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Circle cx={12} cy={12} r={9} />
    <Path d="M9.5 9.6a2.6 2.6 0 1 1 3.6 2.4c-.7.3-1.1.9-1.1 1.6v.5" />
    <Dot color={p.color} cx={12} cy={16.9} />
  </Frame>
);

export const MinusCircleIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Circle cx={12} cy={12} r={9} />
    <Path d="M8.2 12h7.6" />
  </Frame>
);

export const SearchIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Circle cx={10.6} cy={10.6} r={6.6} />
    <Path d="m15.4 15.4 4.8 4.8" />
  </Frame>
);

export const ClockIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Circle cx={12} cy={12} r={9} />
    <Path d="M12 7.2V12l3.4 2.1" />
  </Frame>
);

export const ZapIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Path d="m13.6 2.4-8.2 11.2h5.2l-1.2 8 8.2-11.2h-5.2z" />
  </Frame>
);

export const PlayIcon: IconComponent = (p) => (
  <Frame {...p}>
    <Path d="m7.8 4.8 11.4 7.2-11.4 7.2z" />
  </Frame>
);
