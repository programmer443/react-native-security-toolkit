/**
 * React Native Security Toolkit — example application.
 *
 * The app is a security console rather than a feature checklist: one aggregate
 * run of the native engine, shown five ways. Posture answers "should I trust this
 * device", Checks and Signals expose the evidence behind that answer, Policy
 * turns it into a decision, and Engine shows what the native side reported about
 * itself.
 *
 * Its second job is to be honest. Every verdict on screen is accompanied by what
 * the check cannot establish, `unknown` is never coloured like `secure`, and a
 * missing native module is presented as the build problem it is rather than as a
 * finding about the device.
 */

import { StatusBar } from 'react-native';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { SecurityProvider, useSecurity } from './security/SecurityProvider';
import { LoadingScreen, UnavailableScreen } from './screens/StateScreens';
import { AppNavigator } from './navigation/AppNavigator';
import { ThemeProvider, useTheme } from './theme/theme';
import { fireAndForget } from './utils/async';

export default function App() {
  return (
    <SafeAreaProvider>
      <ThemeProvider>
        <SecurityProvider>
          <Root />
        </SecurityProvider>
      </ThemeProvider>
    </SafeAreaProvider>
  );
}

function Root() {
  const { state, refresh } = useSecurity();
  const { isDark } = useTheme();

  return (
    <>
      <StatusBar barStyle={isDark ? 'light-content' : 'dark-content'} />
      {state.phase === 'loading' ? <LoadingScreen /> : null}
      {state.phase === 'unavailable' ? (
        <UnavailableScreen error={state.error} onRetry={fireAndForget(refresh)} />
      ) : null}
      {state.phase === 'ready' ? (
        <AppNavigator report={state.report} engine={state.engine} />
      ) : null}
    </>
  );
}
