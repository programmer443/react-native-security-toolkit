import { WebView } from 'react-native-webview';

export function Browser({ uri }: { uri: string }) {
  return (
    <WebView
      originWhitelist={['https://app.secure-fixture.test']}
      javaScriptEnabled={false}
      allowFileAccess={false}
      mixedContentMode="never"
      source={{ uri }}
    />
  );
}
