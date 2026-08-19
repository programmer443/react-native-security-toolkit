/**
 * Binary detection.
 *
 * Two layers, because they answer different questions at different costs. The
 * extension list decides whether to read a file at all; the content check
 * decides whether what came back is worth handing to a text rule. A repository
 * can name a 40 MB dylib `helpers.ts`, so neither layer is sufficient alone.
 */

/** Extensions never worth reading. Compiled output, archives, media, key material. */
const BINARY_EXTENSIONS: ReadonlySet<string> = new Set([
  'png',
  'jpg',
  'jpeg',
  'gif',
  'webp',
  'bmp',
  'ico',
  'icns',
  'tiff',
  'psd',
  'mp3',
  'mp4',
  'mov',
  'avi',
  'wav',
  'aac',
  'zip',
  'gz',
  'tgz',
  'bz2',
  'xz',
  'rar',
  '7z',
  'jar',
  'aar',
  'apk',
  'aab',
  'ipa',
  'so',
  'dylib',
  'a',
  'o',
  'class',
  'dex',
  'bin',
  'dat',
  'pdf',
  'ttf',
  'otf',
  'woff',
  'woff2',
  'eot',
  'keystore',
  'jks',
  'p12',
  'pfx',
  'mobileprovision',
  'car',
  'nib',
  'xcuserstate',
  'pyc',
  'wasm',
  'db',
  'sqlite',
  'realm',
]);

/** Whether a path's extension marks it as binary. */
export function hasBinaryExtension(path: string): boolean {
  const basename = path.slice(path.lastIndexOf('/') + 1);
  const dot = basename.lastIndexOf('.');
  if (dot <= 0) {
    return false;
  }
  return BINARY_EXTENSIONS.has(basename.slice(dot + 1).toLowerCase());
}

/** How many leading bytes the content check inspects. */
const SNIFF_BYTES = 8_192;

/**
 * Whether a buffer looks like binary content.
 *
 * A NUL byte settles it — no text encoding this auditor supports produces one.
 * Failing that, a high proportion of control characters is the tell. The
 * threshold is generous: some legitimate source files contain a stray control
 * character, and treating those as binary would silently exclude real code.
 */
export function looksBinary(buffer: Buffer): boolean {
  const length = Math.min(buffer.length, SNIFF_BYTES);
  if (length === 0) {
    return false;
  }

  let controlBytes = 0;
  for (let index = 0; index < length; index += 1) {
    const byte = buffer[index] ?? 0;
    if (byte === 0) {
      return true;
    }
    // Tab, line feed, carriage return and form feed are ordinary in source.
    const isPrintable =
      byte >= 0x20 || byte === 0x09 || byte === 0x0a || byte === 0x0d || byte === 0x0c;
    if (!isPrintable) {
      controlBytes += 1;
    }
  }

  return controlBytes / length > 0.3;
}
