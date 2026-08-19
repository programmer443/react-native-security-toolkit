// Deliberately insecure fixture.
import { WebView } from 'react-native-webview';

export function Browser({ uri }: { uri: string }) {
  return (
    <WebView
      originWhitelist={['*']}
      javaScriptEnabled
      allowFileAccess
      mixedContentMode="always"
      source={{ uri }}
    />
  );
}
