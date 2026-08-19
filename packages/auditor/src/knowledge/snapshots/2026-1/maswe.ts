/**
 * GENERATED FILE - DO NOT EDIT.
 *
 * Regenerate with `pnpm --filter @rn-security/auditor knowledge:sync`.
 * Provenance for this snapshot is recorded in SOURCES.md.
 */

import type { MasweWeakness } from '../../types.js';

export const maswe: readonly MasweWeakness[] = [
  {
    "id": "MASWE-0001",
    "title": "Sensitive Data Stored Unencrypted in Private Storage",
    "masvs": [
      "MASVS-STORAGE-1",
      "MASVS-STORAGE-2",
      "MASVS-CRYPTO-2"
    ],
    "cwe": [
      "CWE-200",
      "CWE-284",
      "CWE-312",
      "CWE-313",
      "CWE-732",
      "CWE-922"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0002",
    "title": "Sensitive Data Stored Unencrypted Outside of Private Storage",
    "masvs": [
      "MASVS-STORAGE-1",
      "MASVS-STORAGE-2"
    ],
    "cwe": [
      "CWE-200",
      "CWE-284",
      "CWE-312",
      "CWE-313",
      "CWE-732",
      "CWE-921",
      "CWE-922"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0003",
    "title": "Cryptographic Keys Stored Outside of Platform Keystore",
    "masvs": [
      "MASVS-STORAGE-1",
      "MASVS-CRYPTO-2"
    ],
    "cwe": [
      "CWE-312",
      "CWE-318",
      "CWE-321"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0004",
    "title": "Sensitive Data Hardcoded in the App Package",
    "masvs": [
      "MASVS-STORAGE-1"
    ],
    "cwe": [
      "CWE-312",
      "CWE-321",
      "CWE-540",
      "CWE-798"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0005",
    "title": "Insertion of Sensitive Data into Logs",
    "masvs": [
      "MASVS-STORAGE-2"
    ],
    "cwe": [
      "CWE-209",
      "CWE-359",
      "CWE-497",
      "CWE-532"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0006",
    "title": "Sensitive Data Not Excluded From Backup",
    "masvs": [
      "MASVS-STORAGE-2"
    ],
    "cwe": [
      "CWE-212",
      "CWE-313"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0007",
    "title": "Improper Encryption",
    "masvs": [
      "MASVS-CRYPTO-1",
      "MASVS-CRYPTO-2"
    ],
    "cwe": [
      "CWE-208",
      "CWE-323",
      "CWE-325",
      "CWE-326",
      "CWE-327",
      "CWE-329",
      "CWE-780"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0008",
    "title": "Improper Hashing",
    "masvs": [
      "MASVS-CRYPTO-1"
    ],
    "cwe": [
      "CWE-328"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0009",
    "title": "Improper Use of Message Authentication Code (MAC)",
    "masvs": [
      "MASVS-CRYPTO-1",
      "MASVS-CRYPTO-2"
    ],
    "cwe": [
      "CWE-208",
      "CWE-323",
      "CWE-327",
      "CWE-354",
      "CWE-807"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0010",
    "title": "Improper Generation of Cryptographic Signatures",
    "masvs": [
      "MASVS-CRYPTO-1",
      "MASVS-CRYPTO-2"
    ],
    "cwe": [
      "CWE-323",
      "CWE-326",
      "CWE-327",
      "CWE-330"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0011",
    "title": "Improper Verification of Cryptographic Signature",
    "masvs": [
      "MASVS-CRYPTO-1"
    ],
    "cwe": [
      "CWE-295",
      "CWE-347"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0012",
    "title": "Improper Random Number Generation",
    "masvs": [
      "MASVS-CRYPTO-1"
    ],
    "cwe": [
      "CWE-332",
      "CWE-337",
      "CWE-338"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0013",
    "title": "Improper Cryptographic Key Generation",
    "masvs": [
      "MASVS-CRYPTO-2"
    ],
    "cwe": [
      "CWE-331",
      "CWE-326",
      "CWE-337",
      "CWE-338",
      "CWE-522"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0014",
    "title": "Improper Cryptographic Key Derivation",
    "masvs": [
      "MASVS-CRYPTO-2"
    ],
    "cwe": [
      "CWE-326",
      "CWE-327",
      "CWE-759",
      "CWE-760",
      "CWE-916"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0015",
    "title": "Cryptographic Key Rotation Not Implemented",
    "masvs": [
      "MASVS-CRYPTO-2"
    ],
    "cwe": [
      "CWE-324"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0016",
    "title": "Cryptographic Key Access Not Restricted",
    "masvs": [
      "MASVS-CRYPTO-2",
      "MASVS-AUTH-2",
      "MASVS-AUTH-3"
    ],
    "cwe": [
      "CWE-284",
      "CWE-306"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0017",
    "title": "Device Secure Lock Not Enforced",
    "masvs": [
      "MASVS-CRYPTO-2"
    ],
    "cwe": [],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0018",
    "title": "Lack of Authentication or Authorization on App Components",
    "masvs": [
      "MASVS-AUTH-1",
      "MASVS-PLATFORM-1",
      "MASVS-STORAGE-2"
    ],
    "cwe": [
      "CWE-306",
      "CWE-749",
      "CWE-862",
      "CWE-863",
      "CWE-923",
      "CWE-926",
      "CWE-939",
      "CWE-940"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0019",
    "title": "Lack of Auto-fill Support for Credential Providers",
    "masvs": [
      "MASVS-AUTH-1",
      "MASVS-AUTH-3"
    ],
    "cwe": [
      "CWE-287",
      "CWE-522"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0020",
    "title": "Local Authentication Can Be Bypassed",
    "masvs": [
      "MASVS-AUTH-2",
      "MASVS-CRYPTO-2"
    ],
    "cwe": [
      "CWE-285",
      "CWE-287",
      "CWE-312",
      "CWE-319",
      "CWE-326",
      "CWE-602",
      "CWE-603",
      "CWE-863",
      "CWE-922"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0021",
    "title": "Fallback to Non-biometric Credentials Allowed for Sensitive Transactions",
    "masvs": [
      "MASVS-AUTH-2"
    ],
    "cwe": [
      "CWE-288",
      "CWE-287"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0022",
    "title": "Crypto Keys Not Invalidated on New Biometric Enrollment",
    "masvs": [
      "MASVS-AUTH-2",
      "MASVS-CRYPTO-2"
    ],
    "cwe": [
      "CWE-287",
      "CWE-522"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0023",
    "title": "Step-Up Authentication Not Implemented for Sensitive Actions",
    "masvs": [
      "MASVS-AUTH-3",
      "MASVS-PLATFORM-3"
    ],
    "cwe": [
      "CWE-306"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0024",
    "title": "Sensitive Data Accessible After Session Termination",
    "masvs": [
      "MASVS-AUTH-3"
    ],
    "cwe": [
      "CWE-285",
      "CWE-287",
      "CWE-613"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0025",
    "title": "Lack of Non-Repudiation for Critical Actions",
    "masvs": [
      "MASVS-AUTH-3"
    ],
    "cwe": [
      "CWE-451",
      "CWE-778"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0026",
    "title": "Network Traffic Not Encrypted",
    "masvs": [
      "MASVS-NETWORK-1"
    ],
    "cwe": [
      "CWE-319"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0027",
    "title": "Insecure Certificate Validation",
    "masvs": [
      "MASVS-NETWORK-1"
    ],
    "cwe": [
      "CWE-295",
      "CWE-297"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0028",
    "title": "Insecure Identity Pinning",
    "masvs": [
      "MASVS-NETWORK-2"
    ],
    "cwe": [
      "CWE-295"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0029",
    "title": "Insecure Deep Links",
    "masvs": [
      "MASVS-PLATFORM-1",
      "MASVS-STORAGE-2",
      "MASVS-CODE-4"
    ],
    "cwe": [
      "CWE-939",
      "CWE-917"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0030",
    "title": "Improper Use of the Clipboard",
    "masvs": [
      "MASVS-PLATFORM-1",
      "MASVS-STORAGE-2"
    ],
    "cwe": [
      "CWE-200",
      "CWE-668"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0031",
    "title": "Allowing Untrusted App Extensions",
    "masvs": [
      "MASVS-PLATFORM-1",
      "MASVS-STORAGE-2"
    ],
    "cwe": [
      "CWE-829"
    ],
    "platforms": [
      "ios"
    ]
  },
  {
    "id": "MASWE-0032",
    "title": "Insecure Intents",
    "masvs": [
      "MASVS-PLATFORM-1",
      "MASVS-STORAGE-2"
    ],
    "cwe": [
      "CWE-927",
      "CWE-940"
    ],
    "platforms": [
      "android"
    ]
  },
  {
    "id": "MASWE-0033",
    "title": "Sensitive Native Functionality Exposed in WebViews",
    "masvs": [
      "MASVS-PLATFORM-2",
      "MASVS-STORAGE-2"
    ],
    "cwe": [
      "CWE-749",
      "CWE-94"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0034",
    "title": "WebViews Allow Access to Local Resources with Untrusted Content",
    "masvs": [
      "MASVS-PLATFORM-2",
      "MASVS-STORAGE-2",
      "MASVS-CODE-4"
    ],
    "cwe": [
      "CWE-22",
      "CWE-79",
      "CWE-200",
      "CWE-669"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0035",
    "title": "WebViews Loading Untrusted Content",
    "masvs": [
      "MASVS-PLATFORM-2",
      "MASVS-CODE-4"
    ],
    "cwe": [
      "CWE-79",
      "CWE-601",
      "CWE-829"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0036",
    "title": "Unnecessary Exposure of Sensitive Data via the User Interface",
    "masvs": [
      "MASVS-PLATFORM-3",
      "MASVS-STORAGE-2"
    ],
    "cwe": [
      "CWE-200",
      "CWE-359"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0037",
    "title": "Unnecessary Exposure of Sensitive Data via Notifications",
    "masvs": [
      "MASVS-PLATFORM-3",
      "MASVS-STORAGE-2"
    ],
    "cwe": [
      "CWE-200",
      "CWE-359"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0038",
    "title": "Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings",
    "masvs": [
      "MASVS-PLATFORM-3",
      "MASVS-STORAGE-2"
    ],
    "cwe": [
      "CWE-200",
      "CWE-359"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0039",
    "title": "App Vulnerable to Overlay Attacks",
    "masvs": [
      "MASVS-PLATFORM-3",
      "MASVS-CODE-1"
    ],
    "cwe": [
      "CWE-1021"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0040",
    "title": "Sensitive Data Leaked via Accessibility Services",
    "masvs": [
      "MASVS-PLATFORM-3",
      "MASVS-STORAGE-2"
    ],
    "cwe": [
      "CWE-200",
      "CWE-359"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0041",
    "title": "Running on a Recent Platform Version Not Ensured",
    "masvs": [
      "MASVS-CODE-1"
    ],
    "cwe": [
      "CWE-451",
      "CWE-693",
      "CWE-1104",
      "CWE-1357"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0042",
    "title": "Latest Platform Version Not Targeted",
    "masvs": [
      "MASVS-CODE-1"
    ],
    "cwe": [
      "CWE-693",
      "CWE-1357"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0043",
    "title": "Enforced Updating Not Implemented",
    "masvs": [
      "MASVS-CODE-2"
    ],
    "cwe": [
      "CWE-602",
      "CWE-693"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0044",
    "title": "Dependencies with Known Vulnerabilities",
    "masvs": [
      "MASVS-CODE-3"
    ],
    "cwe": [
      "CWE-1395",
      "CWE-1357"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0045",
    "title": "Compiler-Provided Security Features Not Used",
    "masvs": [
      "MASVS-CODE-3",
      "MASVS-CODE-4"
    ],
    "cwe": [],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0046",
    "title": "Use of Deprecated APIs or Functionality",
    "masvs": [
      "MASVS-CODE-3",
      "MASVS-CRYPTO-2"
    ],
    "cwe": [
      "CWE-327",
      "CWE-477",
      "CWE-522"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0047",
    "title": "Using Non-Standard APIs for Security-Critical Functionality",
    "masvs": [
      "MASVS-CODE-3",
      "MASVS-AUTH-1",
      "MASVS-CRYPTO-1",
      "MASVS-NETWORK-1"
    ],
    "cwe": [
      "CWE-287",
      "CWE-326",
      "CWE-327",
      "CWE-1240"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0048",
    "title": "Malicious Code Included in the App",
    "masvs": [
      "MASVS-CODE-3"
    ],
    "cwe": [
      "CWE-506",
      "CWE-507",
      "CWE-511"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0049",
    "title": "Unsafe Dynamic Code Loading",
    "masvs": [
      "MASVS-CODE-4"
    ],
    "cwe": [
      "CWE-494"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0050",
    "title": "Unsafe Handling of Untrusted Data",
    "masvs": [
      "MASVS-CODE-4"
    ],
    "cwe": [
      "CWE-20",
      "CWE-22",
      "CWE-73",
      "CWE-89",
      "CWE-116",
      "CWE-345",
      "CWE-348",
      "CWE-349",
      "CWE-502",
      "CWE-611",
      "CWE-924"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0051",
    "title": "Root/Jailbreak Detection Not Implemented",
    "masvs": [
      "MASVS-RESILIENCE-1",
      "MASVS-RESILIENCE-4"
    ],
    "cwe": [
      "CWE-1326"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0052",
    "title": "App Virtualization Environment Detection Not Implemented",
    "masvs": [
      "MASVS-RESILIENCE-1"
    ],
    "cwe": [
      "CWE-693"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0053",
    "title": "Emulated or Virtual Device Detection Not Implemented",
    "masvs": [
      "MASVS-RESILIENCE-1",
      "MASVS-RESILIENCE-4"
    ],
    "cwe": [],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0054",
    "title": "Device Attestation Not Implemented",
    "masvs": [
      "MASVS-RESILIENCE-1"
    ],
    "cwe": [],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0055",
    "title": "Malware Detection Not Implemented",
    "masvs": [
      "MASVS-RESILIENCE-2"
    ],
    "cwe": [
      "CWE-693"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0056",
    "title": "App Attestation Not Implemented",
    "masvs": [
      "MASVS-RESILIENCE-2"
    ],
    "cwe": [
      "CWE-347"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0057",
    "title": "App Resources Integrity Not Verified",
    "masvs": [
      "MASVS-RESILIENCE-2",
      "MASVS-CODE-4"
    ],
    "cwe": [
      "CWE-471"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0058",
    "title": "Runtime Code Integrity Not Verified",
    "masvs": [
      "MASVS-RESILIENCE-2"
    ],
    "cwe": [],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0059",
    "title": "Code Obfuscation Not Implemented",
    "masvs": [
      "MASVS-RESILIENCE-3"
    ],
    "cwe": [
      "CWE-693"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0060",
    "title": "Resource Obfuscation Not Implemented",
    "masvs": [
      "MASVS-RESILIENCE-3"
    ],
    "cwe": [
      "CWE-693"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0061",
    "title": "Debug Artifacts Not Removed",
    "masvs": [
      "MASVS-RESILIENCE-3"
    ],
    "cwe": [
      "CWE-489",
      "CWE-497",
      "CWE-540",
      "CWE-912",
      "CWE-1295"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0062",
    "title": "No Application-Level Payload Encryption",
    "masvs": [
      "MASVS-RESILIENCE-3",
      "MASVS-NETWORK-1"
    ],
    "cwe": [
      "CWE-319"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0063",
    "title": "Debug Mechanisms Not Disabled",
    "masvs": [
      "MASVS-RESILIENCE-4",
      "MASVS-PLATFORM-2"
    ],
    "cwe": [
      "CWE-489"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0064",
    "title": "Debugger Detection Not Implemented",
    "masvs": [
      "MASVS-RESILIENCE-4"
    ],
    "cwe": [],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0065",
    "title": "Dynamic Analysis Tools Detection Not Implemented",
    "masvs": [
      "MASVS-RESILIENCE-4"
    ],
    "cwe": [],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0066",
    "title": "Inadequate Permission Management",
    "masvs": [
      "MASVS-PRIVACY-1"
    ],
    "cwe": [
      "CWE-250"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0067",
    "title": "Lack of Anonymization or Pseudonymisation Measures",
    "masvs": [
      "MASVS-PRIVACY-2"
    ],
    "cwe": [
      "CWE-359"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0068",
    "title": "Incorrect Use of Identifiers for User Tracking",
    "masvs": [
      "MASVS-PRIVACY-2"
    ],
    "cwe": [
      "CWE-359"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0069",
    "title": "Usage of Non-Privacy-Preserving Functionality",
    "masvs": [
      "MASVS-PRIVACY-2"
    ],
    "cwe": [
      "CWE-359"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0070",
    "title": "Inadequate Awareness for Privacy Relevant Actions",
    "masvs": [
      "MASVS-PRIVACY-2"
    ],
    "cwe": [
      "CWE-359"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0071",
    "title": "Inadequate Defaults for Privacy Relevant Actions",
    "masvs": [
      "MASVS-PRIVACY-2"
    ],
    "cwe": [
      "CWE-359"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0072",
    "title": "Inadequate Privacy Policy",
    "masvs": [
      "MASVS-PRIVACY-3"
    ],
    "cwe": [
      "CWE-359"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0073",
    "title": "Inadequate Data Collection Declarations",
    "masvs": [
      "MASVS-PRIVACY-3",
      "MASVS-PRIVACY-1"
    ],
    "cwe": [
      "CWE-359"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0074",
    "title": "Inadequate Tracking Domains Declarations",
    "masvs": [
      "MASVS-PRIVACY-3"
    ],
    "cwe": [
      "CWE-359"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0075",
    "title": "Non-Reproducible Builds",
    "masvs": [
      "MASVS-PRIVACY-3"
    ],
    "cwe": [
      "CWE-1357",
      "CWE-494"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0076",
    "title": "Lack of Proper Data Management Controls",
    "masvs": [
      "MASVS-PRIVACY-4"
    ],
    "cwe": [
      "CWE-359"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0077",
    "title": "Inadequate Data Visibility Controls",
    "masvs": [
      "MASVS-PRIVACY-4"
    ],
    "cwe": [
      "CWE-359"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  },
  {
    "id": "MASWE-0078",
    "title": "Inadequate or Ambiguous User Consent Mechanisms",
    "masvs": [
      "MASVS-PRIVACY-4"
    ],
    "cwe": [
      "CWE-200",
      "CWE-285",
      "CWE-358",
      "CWE-359"
    ],
    "platforms": [
      "android",
      "ios"
    ]
  }
];
