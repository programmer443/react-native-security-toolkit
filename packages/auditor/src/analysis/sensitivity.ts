/**
 * Deciding whether a name refers to something sensitive.
 *
 * This one judgement drives the difference between a scanner people use and one
 * they switch off. "Flag every `AsyncStorage.setItem`" and "flag every
 * `console.log`" are the two failure modes the brief calls out repeatedly, and
 * both come from skipping this step.
 *
 * The rule of thumb encoded here: a *name* is evidence, not proof. `userToken`
 * is sensitive; `tokenizer`, `tokenCount` and `csrfTokenPlaceholder` are not.
 * Matching is word-aware for that reason, and there is an explicit list of
 * benign compounds that would otherwise trip it.
 */

/** Categories of sensitive data, used to phrase findings and choose severity. */
export type SensitiveKind =
  | 'credential'
  | 'token'
  | 'cryptographic-key'
  | 'personal-data'
  | 'financial'
  | 'health'
  | 'device-identifier';

interface SensitiveTerm {
  readonly words: readonly string[];
  readonly kind: SensitiveKind;
}

const TERMS: readonly SensitiveTerm[] = [
  { words: ['password', 'passwd', 'passphrase', 'credential', 'credentials'], kind: 'credential' },
  { words: ['secret', 'apikey', 'apisecret', 'clientsecret', 'appsecret'], kind: 'credential' },
  {
    words: ['token', 'accesstoken', 'refreshtoken', 'idtoken', 'bearer', 'jwt', 'authorization'],
    kind: 'token',
  },
  { words: ['session', 'sessionid', 'cookie', 'setcookie'], kind: 'token' },
  { words: ['otp', 'mfa', 'twofactor', '2fa', 'pin', 'pincode'], kind: 'credential' },
  {
    words: ['privatekey', 'secretkey', 'signingkey', 'encryptionkey', 'masterkey', 'keystore'],
    kind: 'cryptographic-key',
  },
  { words: ['mnemonic', 'seedphrase', 'recoveryphrase', 'walletkey'], kind: 'cryptographic-key' },
  {
    words: ['ssn', 'socialsecurity', 'passport', 'nationalid', 'nric', 'aadhaar', 'taxid'],
    kind: 'personal-data',
  },
  { words: ['dateofbirth', 'dob', 'address', 'phonenumber', 'email'], kind: 'personal-data' },
  {
    words: [
      'cardnumber',
      'creditcard',
      'debitcard',
      'pan',
      'cvv',
      'cvc',
      'iban',
      'sortcode',
      'accountnumber',
    ],
    kind: 'financial',
  },
  { words: ['medical', 'diagnosis', 'prescription', 'healthrecord'], kind: 'health' },
  { words: ['imei', 'advertisingid', 'idfa', 'macaddress'], kind: 'device-identifier' },
];

/**
 * Names that contain a sensitive word but are not sensitive.
 *
 * Every entry here comes from a real false positive shape: a tokenizer is not a
 * token, a password *field label* is not a password, and a public key is public.
 */
const BENIGN_COMPOUNDS: readonly string[] = [
  'tokenizer',
  'tokenize',
  'tokencount',
  'tokenlimit',
  'tokenizerconfig',
  'maxtokens',
  'passwordlabel',
  'passwordplaceholder',
  'passwordhint',
  'passwordfield',
  'passwordinput',
  'forgotpassword',
  'changepassword',
  'resetpassword',
  'passwordstrength',
  'publickey',
  'keyboard',
  'keyextractor',
  'keycode',
  'keyname',
  'keypath',
  'emailplaceholder',
  'emaillabel',
  'addressline',
  'addressbook',
  'panel',
  'panresponder',
  'pangesture',
  'sessionstorage',
  'cookiepolicy',
  'cookiebanner',
];

/** Strips separators and case so `user_token`, `userToken` and `USER-TOKEN` compare equal. */
function normalise(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/** Splits an identifier into lowercase words across camelCase, snake_case and kebab-case. */
export function splitWords(name: string): readonly string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+|\s+/)
    .map((word) => word.toLowerCase())
    .filter((word) => word.length > 0);
}

/**
 * What kind of sensitive data a name suggests, if any.
 *
 * Both the whole normalised name and its individual words are considered, so
 * `x-api-key`, `apiKey` and `api_key` all match while `keyboardHeight` does not.
 */
export function sensitiveKindOf(name: string): SensitiveKind | undefined {
  const normalised = normalise(name);
  if (normalised === '') {
    return undefined;
  }

  if (BENIGN_COMPOUNDS.some((benign) => normalised === benign || normalised.includes(benign))) {
    return undefined;
  }

  for (const term of TERMS) {
    if (term.words.some((word) => normalised === word)) {
      return term.kind;
    }
  }

  const words = splitWords(name);
  for (const term of TERMS) {
    if (term.words.some((word) => words.includes(word))) {
      return term.kind;
    }
  }

  // Compound names such as `userAccessToken` or `stripeApiKey`, where the
  // sensitive word is a suffix rather than a standalone word.
  for (const term of TERMS) {
    for (const word of term.words) {
      if (word.length >= 5 && normalised.endsWith(word)) {
        return term.kind;
      }
    }
  }

  return undefined;
}

/** Whether a name suggests sensitive data. */
export function isSensitiveName(name: string): boolean {
  return sensitiveKindOf(name) !== undefined;
}

/** Human-readable description of a category, for finding text. */
export function describeSensitiveKind(kind: SensitiveKind): string {
  switch (kind) {
    case 'credential':
      return 'a credential';
    case 'token':
      return 'an authentication token or session identifier';
    case 'cryptographic-key':
      return 'cryptographic key material';
    case 'personal-data':
      return 'personally identifiable information';
    case 'financial':
      return 'financial account data';
    case 'health':
      return 'health data';
    case 'device-identifier':
      return 'a device identifier';
  }
}

/**
 * Masks a value so a report can show what was matched without carrying the
 * secret itself.
 *
 * A findings report is copied into pull requests, CI logs and issue trackers —
 * places a credential travels much further than the source file it came from.
 * Keeping a short prefix preserves the ability to grep for the value in the
 * codebase without reproducing it.
 */
export function maskSecret(value: string): string {
  if (value.length <= 8) {
    return '*'.repeat(value.length);
  }
  return `${value.slice(0, 4)}${'*'.repeat(Math.min(value.length - 4, 20))}`;
}
