/**
 * Holds the one security report the whole app renders.
 *
 * A real application calls `checkAll()` once at startup and decides what to do
 * with the answer; it does not re-check on every screen. This provider models
 * that: one aggregate run, shared by every screen, refreshable on demand.
 *
 * Two things here are demonstrations rather than plumbing:
 *
 * - **`rerunCheck`** goes through the focused single-check module
 *   (`RootDetection.getStatus()` and friends) rather than `checkAll()`, so the
 *   example exercises both public code paths.
 * - **`setDevelopmentMode`** re-scores the existing results with the public
 *   `evaluateRisk()` instead of re-running the native engine. That is the point
 *   worth showing: development mode changes *interpretation*, not findings. The
 *   check results underneath are byte-for-byte identical.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import {
  SecurityToolkit,
  evaluateRisk,
  isSecurityToolkitError,
  type CheckId,
  type NativeEngineInfo,
  type SecurityCheckResult,
  type SecurityReport,
} from 'react-native-security-toolkit';
import { CHECK_MODULES } from './catalog';

/**
 * The example app's own identity, and the only configuration the toolkit needs
 * to make integrity checking meaningful. A shipping app would use the signing
 * fingerprint it actually published — see `docs/runtime/integrity.md`.
 */
const INTEGRITY_EXPECTATIONS = {
  expectedPackageName: 'securitytoolkit.example',
  expectedInstallers: ['com.android.vending'],
  expectedBundleIdentifier: 'securitytoolkit.example',
} as const;

/**
 * Raised from the 5 s default.
 *
 * `checkAll()` runs every detector in one native call, and a debug build on an
 * emulator is several times slower than a release build on hardware — filesystem
 * probes and a Keystore key generation in particular. The production default is
 * the right default; an example that a reader runs on an emulator first needs
 * more headroom than that, and pretending otherwise would greet them with a
 * timeout instead of a dashboard.
 */
const NATIVE_TIMEOUT_MS = 20_000;

/**
 * The app's baseline options.
 *
 * `configure()` **replaces** the configuration rather than merging into it, so
 * every call has to carry the full set. Sending `{ developmentMode: true }` on
 * its own would silently reset the integrity expectations and the timeout above
 * back to their defaults.
 */
const BASE_OPTIONS = {
  integrity: INTEGRITY_EXPECTATIONS,
  nativeTimeoutMs: NATIVE_TIMEOUT_MS,
} as const;

export interface SecurityUnavailable {
  readonly code: string;
  readonly message: string;
}

export type SecurityState =
  | { readonly phase: 'loading' }
  | {
      readonly phase: 'ready';
      readonly engine: NativeEngineInfo;
      readonly report: SecurityReport;
    }
  | { readonly phase: 'unavailable'; readonly error: SecurityUnavailable };

export interface SecurityContextValue {
  readonly state: SecurityState;
  readonly refreshing: boolean;
  readonly developmentMode: boolean;
  /** Re-runs every check on this platform. */
  readonly refresh: () => Promise<void>;
  /** Re-runs one check through its own module and re-scores the report. */
  readonly rerunCheck: (id: CheckId) => Promise<SecurityCheckResult | undefined>;
  readonly setDevelopmentMode: (enabled: boolean) => void;
}

const SecurityContext = createContext<SecurityContextValue | undefined>(undefined);

export function SecurityProvider({ children }: { readonly children: ReactNode }) {
  const [state, setState] = useState<SecurityState>({ phase: 'loading' });
  const [refreshing, setRefreshing] = useState(false);
  const [developmentMode, setDevMode] = useState(false);
  /** Guards against a resolved promise writing state after unmount. */
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const load = useCallback(async () => {
    try {
      // `checkAll()` rejects only when the native module is missing; every
      // device condition arrives as a result. So this catch means "not linked",
      // not "insecure device".
      const [engine, report] = await Promise.all([
        SecurityToolkit.getEngineInfo(),
        SecurityToolkit.checkAll(),
      ]);

      // Logged so a run is verifiable from the Metro output as well as on screen.
      console.log('[rnsec] engine', JSON.stringify(engine));
      console.log('[rnsec] report', JSON.stringify(report));

      if (mounted.current) {
        setState({ phase: 'ready', engine, report });
      }
    } catch (error: unknown) {
      console.log('[rnsec] native engine unreachable', String(error));
      if (mounted.current) {
        setState({
          phase: 'unavailable',
          error: {
            code: isSecurityToolkitError(error) ? error.code : 'UNKNOWN',
            message: error instanceof Error ? error.message : String(error),
          },
        });
      }
    }
  }, []);

  useEffect(() => {
    SecurityToolkit.configure(BASE_OPTIONS);
    // `load` resolves in every case — it converts a missing native module into
    // state rather than a rejection — so there is nothing to catch here.
    load();
  }, [load]);

  const refresh = useCallback(async () => {
    setRefreshing(true);
    await load();
    if (mounted.current) {
      setRefreshing(false);
    }
  }, [load]);

  const rerunCheck = useCallback(
    async (id: CheckId): Promise<SecurityCheckResult | undefined> => {
      const result = await CHECK_MODULES[id]();
      console.log('[rnsec] rerun', id, JSON.stringify(result));

      if (!mounted.current) {
        return result;
      }

      setState((current) => {
        if (current.phase !== 'ready') {
          return current;
        }
        return {
          ...current,
          report: withCheck(current.report, result, developmentMode),
        };
      });

      return result;
    },
    [developmentMode]
  );

  const setDevelopmentMode = useCallback((enabled: boolean) => {
    setDevMode(enabled);
    SecurityToolkit.configure({ ...BASE_OPTIONS, developmentMode: enabled });
    setState((current) =>
      current.phase === 'ready' ? { ...current, report: rescore(current.report, enabled) } : current
    );
  }, []);

  const value = useMemo<SecurityContextValue>(
    () => ({ state, refreshing, developmentMode, refresh, rerunCheck, setDevelopmentMode }),
    [state, refreshing, developmentMode, refresh, rerunCheck, setDevelopmentMode]
  );

  return <SecurityContext.Provider value={value}>{children}</SecurityContext.Provider>;
}

export function useSecurity(): SecurityContextValue {
  const value = useContext(SecurityContext);
  if (value === undefined) {
    throw new Error('useSecurity() must be used inside <SecurityProvider>');
  }
  return value;
}

/** Convenience for screens that only render once a report exists. */
export function useReport(): SecurityReport | undefined {
  const { state } = useSecurity();
  return state.phase === 'ready' ? state.report : undefined;
}

function withCheck(
  report: SecurityReport,
  result: SecurityCheckResult,
  developmentMode: boolean
): SecurityReport {
  const checks = { ...report.checks, [result.id]: result };
  const risk = evaluateRisk(checks, { developmentMode });
  return {
    ...report,
    checks,
    risk,
    compromised: risk.level === 'high' || risk.level === 'critical',
    checkedAt: result.checkedAt,
  };
}

function rescore(report: SecurityReport, developmentMode: boolean): SecurityReport {
  const risk = evaluateRisk(report.checks, { developmentMode });
  return {
    ...report,
    risk,
    compromised: risk.level === 'high' || risk.level === 'critical',
  };
}
