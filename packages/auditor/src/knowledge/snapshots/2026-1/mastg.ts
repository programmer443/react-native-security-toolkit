/**
 * GENERATED FILE - DO NOT EDIT.
 *
 * Regenerate with `pnpm --filter @rn-security/auditor knowledge:sync`.
 * Provenance for this snapshot is recorded in SOURCES.md.
 */

import type { MastgTest } from '../../types.js';

export const mastg: readonly MastgTest[] = [
  {
    "id": "MASTG-TEST-0200",
    "title": "Files Written to External Storage",
    "platform": "android",
    "weakness": "MASWE-0002",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0201",
    "title": "Runtime Use of APIs to Access External Storage",
    "platform": "android",
    "weakness": "MASWE-0002",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0202",
    "title": "References to APIs and Permissions for Accessing External Storage",
    "platform": "android",
    "weakness": "MASWE-0002",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0203",
    "title": "Runtime Use of Logging APIs",
    "platform": "android",
    "weakness": "MASWE-0005",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0204",
    "title": "Insecure Random API Usage",
    "platform": "android",
    "weakness": "MASWE-0012",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0205",
    "title": "Non-random Sources Usage",
    "platform": "android",
    "weakness": "MASWE-0012",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0206",
    "title": "Undeclared PII in Network Traffic Capture",
    "platform": "android",
    "weakness": "MASWE-0073",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0207",
    "title": "Runtime Storage of Unencrypted Data in the App Sandbox",
    "platform": "android",
    "weakness": "MASWE-0001",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0208",
    "title": "Insufficient Key Sizes",
    "platform": "android",
    "weakness": "MASWE-0013",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0209",
    "title": "Insufficient Key Sizes",
    "platform": "ios",
    "weakness": "MASWE-0013",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0210",
    "title": "Broken Symmetric Encryption Algorithms",
    "platform": "ios",
    "weakness": "MASWE-0007",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0211",
    "title": "Broken Hashing Algorithms",
    "platform": "ios",
    "weakness": "MASWE-0008",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0212",
    "title": "Use of Hardcoded Cryptographic Keys in Code",
    "platform": "android",
    "weakness": "MASWE-0003",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0213",
    "title": "Use of Hardcoded Cryptographic Keys in Code",
    "platform": "ios",
    "weakness": "MASWE-0003",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0214",
    "title": "Hardcoded Cryptographic Keys in Files",
    "platform": "ios",
    "weakness": "MASWE-0003",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0215",
    "title": "Sensitive Data Not Marked For Backup Exclusion",
    "platform": "ios",
    "weakness": "MASWE-0006",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0216",
    "title": "Sensitive Data Not Excluded From Backup",
    "platform": "android",
    "weakness": "MASWE-0006",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0217",
    "title": "Insecure TLS Protocols Explicitly Allowed in Code",
    "platform": "android",
    "weakness": "MASWE-0026",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0218",
    "title": "Insecure TLS Protocols in Network Traffic",
    "platform": "android",
    "weakness": "MASWE-0026",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0219",
    "title": "Testing for Debugging Symbols",
    "platform": "ios",
    "weakness": "MASWE-0061",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0220",
    "title": "Usage of Outdated Code Signature Format",
    "platform": "ios",
    "weakness": "MASWE-0056",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0221",
    "title": "Broken Symmetric Encryption Algorithms",
    "platform": "android",
    "weakness": "MASWE-0007",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0222",
    "title": "Position Independent Code (PIC) Not Enabled",
    "platform": "android",
    "weakness": "MASWE-0045",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0223",
    "title": "Stack Canaries Not Enabled",
    "platform": "android",
    "weakness": "MASWE-0045",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0228",
    "title": "Position Independent Code (PIC) not Enabled",
    "platform": "ios",
    "weakness": "MASWE-0045",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0229",
    "title": "Stack Canaries Not enabled",
    "platform": "ios",
    "weakness": "MASWE-0045",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0230",
    "title": "Automatic Reference Counting (ARC) not enabled",
    "platform": "ios",
    "weakness": "MASWE-0045",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0231",
    "title": "References to Logging APIs",
    "platform": "android",
    "weakness": "MASWE-0005",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0232",
    "title": "Broken Symmetric Encryption Modes",
    "platform": "android",
    "weakness": "MASWE-0007",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0233",
    "title": "Hardcoded HTTP URLs",
    "platform": "android",
    "weakness": "MASWE-0026",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0234",
    "title": "Missing Implementation of Server Hostname Verification with SSLSockets",
    "platform": "android",
    "weakness": "MASWE-0027",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0235",
    "title": "Android App Configurations Allowing Cleartext Traffic",
    "platform": "android",
    "weakness": "MASWE-0026",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0236",
    "title": "Cleartext Traffic Observed on the Network",
    "platform": "network",
    "weakness": "MASWE-0026",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0237",
    "title": "Cross-Platform Framework Configurations Allowing Cleartext Traffic",
    "platform": "android",
    "weakness": "MASWE-0026",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0238",
    "title": "Runtime Use of Network APIs Transmitting Cleartext Traffic",
    "platform": "android",
    "weakness": "MASWE-0026",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0239",
    "title": "Using low-level APIs (e.g. Socket) to set up a custom HTTP connection",
    "platform": "android",
    "weakness": "MASWE-0026",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0240",
    "title": "Jailbreak Detection in Code",
    "platform": "ios",
    "weakness": "MASWE-0051",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0241",
    "title": "Runtime Use of Jailbreak Detection Techniques",
    "platform": "ios",
    "weakness": "MASWE-0051",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0242",
    "title": "Missing Certificate Pinning in Network Security Configuration",
    "platform": "android",
    "weakness": "MASWE-0028",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0243",
    "title": "Expired Certificate Pins in the Network Security Configuration",
    "platform": "android",
    "weakness": "MASWE-0028",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0244",
    "title": "Missing Certificate Pinning in Network Traffic",
    "platform": "network",
    "weakness": "MASWE-0028",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0245",
    "title": "References to Platform Version APIs",
    "platform": "android",
    "weakness": "MASWE-0041",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0246",
    "title": "Runtime Use of Secure Screen Lock Detection APIs",
    "platform": "ios",
    "weakness": "MASWE-0017",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0248",
    "title": "References to APIs for Detecting Secure Screen Lock",
    "platform": "ios",
    "weakness": "MASWE-0017",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0250",
    "title": "References to Content Provider Access in WebViews",
    "platform": "android",
    "weakness": "MASWE-0034",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0251",
    "title": "Runtime Use of Content Provider Access APIs in WebViews",
    "platform": "android",
    "weakness": "MASWE-0034",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0252",
    "title": "References to Local File Access in WebViews",
    "platform": "android",
    "weakness": "MASWE-0034",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0253",
    "title": "Runtime Use of Local File Access APIs in WebViews",
    "platform": "android",
    "weakness": "MASWE-0034",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0254",
    "title": "Dangerous App Permissions",
    "platform": "android",
    "weakness": "MASWE-0066",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0255",
    "title": "Permission Requests Not Minimized",
    "platform": "android",
    "weakness": "MASWE-0066",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0256",
    "title": "Missing Permission Rationale",
    "platform": "android",
    "weakness": "MASWE-0066",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0257",
    "title": "Not Resetting Unused Permissions",
    "platform": "android",
    "weakness": "MASWE-0066",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0258",
    "title": "References to Keyboard Caching Attributes in UI Elements",
    "platform": "android",
    "weakness": "MASWE-0036",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0261",
    "title": "Debuggable Entitlement Enabled in the entitlements.plist",
    "platform": "ios",
    "weakness": "MASWE-0063",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0262",
    "title": "References to Backup Configurations Not Excluding Sensitive Data",
    "platform": "android",
    "weakness": "MASWE-0006",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0266",
    "title": "References to APIs for Event-Bound Biometric Authentication",
    "platform": "ios",
    "weakness": "MASWE-0020",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0267",
    "title": "Runtime Use Of Event-Bound Biometric Authentication",
    "platform": "ios",
    "weakness": "MASWE-0020",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0268",
    "title": "References to APIs Allowing Fallback to Non-Biometric Authentication",
    "platform": "ios",
    "weakness": "MASWE-0021",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0269",
    "title": "Runtime Use Of APIs Allowing Fallback to Non-Biometric Authentication",
    "platform": "ios",
    "weakness": "MASWE-0021",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0270",
    "title": "References to APIs Detecting Biometric Enrollment Changes",
    "platform": "ios",
    "weakness": "MASWE-0022",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0271",
    "title": "Runtime Use Of APIs Detecting Biometric Enrollment Changes",
    "platform": "ios",
    "weakness": "MASWE-0022",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0272",
    "title": "Identify Dependencies with Known Vulnerabilities in the Android Project",
    "platform": "android",
    "weakness": "MASWE-0044",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0273",
    "title": "Identify Dependencies with Known Vulnerabilities by Scanning Dependency Managers Artifacts",
    "platform": "ios",
    "weakness": "MASWE-0044",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0274",
    "title": "Dependencies with Known Vulnerabilities in the App's SBOM",
    "platform": "android",
    "weakness": "MASWE-0044",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0275",
    "title": "Dependencies with Known Vulnerabilities in the App's SBOM",
    "platform": "ios",
    "weakness": "MASWE-0044",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0276",
    "title": "Use of the iOS General Pasteboard",
    "platform": "ios",
    "weakness": "MASWE-0036",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0277",
    "title": "Sensitive Data in the iOS General Pasteboard at Runtime",
    "platform": "ios",
    "weakness": "MASWE-0036",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0278",
    "title": "Pasteboard Contents Not Cleared After Use",
    "platform": "ios",
    "weakness": "MASWE-0036",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0279",
    "title": "Pasteboard Contents Not Expiring",
    "platform": "ios",
    "weakness": "MASWE-0036",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0280",
    "title": "Pasteboard Contents Not Restricted to Local Device",
    "platform": "ios",
    "weakness": "MASWE-0036",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0281",
    "title": "Undeclared Known Tracking Domains",
    "platform": "ios",
    "weakness": "MASWE-0074",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0282",
    "title": "Unsafe Custom Trust Evaluation",
    "platform": "android",
    "weakness": "MASWE-0027",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0283",
    "title": "Incorrect Implementation of Server Hostname Verification",
    "platform": "android",
    "weakness": "MASWE-0027",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0284",
    "title": "Incorrect SSL Error Handling in WebViews",
    "platform": "android",
    "weakness": "MASWE-0027",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0285",
    "title": "Outdated Android Version Allowing Trust in User-Provided CAs",
    "platform": "android",
    "weakness": "MASWE-0027",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0286",
    "title": "Network Security Configuration Allowing Trust in User-Provided CAs",
    "platform": "android",
    "weakness": "MASWE-0027",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0287",
    "title": "Runtime Storage of Unencrypted Data via the SharedPreferences API",
    "platform": "android",
    "weakness": "MASWE-0001",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0289",
    "title": "Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding",
    "platform": "android",
    "weakness": "MASWE-0038",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0290",
    "title": "Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding",
    "platform": "ios",
    "weakness": "MASWE-0038",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0291",
    "title": "References to Screen Capturing Prevention APIs",
    "platform": "android",
    "weakness": "MASWE-0038",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0292",
    "title": "`setRecentsScreenshotEnabled` Not Used to Prevent Screenshots When Backgrounded",
    "platform": "android",
    "weakness": "MASWE-0038",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0293",
    "title": "`setSecure` Not Used to Prevent Screenshots in SurfaceViews",
    "platform": "android",
    "weakness": "MASWE-0038",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0294",
    "title": "`SecureOn` Not Used to Prevent Screenshots in Compose Dialogs",
    "platform": "android",
    "weakness": "MASWE-0038",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0295",
    "title": "GMS Security Provider Not Updated",
    "platform": "android",
    "weakness": "MASWE-0027",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0296",
    "title": "Sensitive Data Exposure in Logs",
    "platform": "ios",
    "weakness": "MASWE-0005",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0297",
    "title": "Sensitive Data Exposure Through Logging APIs",
    "platform": "ios",
    "weakness": "MASWE-0005",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0298",
    "title": "Runtime Monitoring of Files Eligible for Backup",
    "platform": "ios",
    "weakness": "MASWE-0006",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0299",
    "title": "Data Protection Classes for Files in Private Storage",
    "platform": "ios",
    "weakness": "MASWE-0001",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0300",
    "title": "References to APIs for Storing Unencrypted Data in Private Storage",
    "platform": "ios",
    "weakness": "MASWE-0001",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0301",
    "title": "Runtime Use of APIs for Storing Unencrypted Data in Private Storage",
    "platform": "ios",
    "weakness": "MASWE-0001",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0302",
    "title": "Sensitive Data Unencrypted in Private Storage Files",
    "platform": "ios",
    "weakness": "MASWE-0001",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0303",
    "title": "References to APIs for Storing Unencrypted Data in Shared Storage",
    "platform": "ios",
    "weakness": "MASWE-0002",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0304",
    "title": "References to Sensitive Data Unencrypted via Android Room Database",
    "platform": "android",
    "weakness": "MASWE-0001",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0305",
    "title": "Sensitive Data Stored Unencrypted via DataStore",
    "platform": "android",
    "weakness": "MASWE-0001",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0306",
    "title": "References to Sensitive Data Stored Unencrypted via Android Room DB",
    "platform": "android",
    "weakness": "MASWE-0001",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0307",
    "title": "References to Asymmetric Key Pairs Used For Multiple Purposes",
    "platform": "android",
    "weakness": "MASWE-0007",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0308",
    "title": "Runtime Use of Asymmetric Key Pairs Used For Multiple Purposes",
    "platform": "android",
    "weakness": "MASWE-0007",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0309",
    "title": "References to Reused Initialization Vectors in Symmetric Encryption",
    "platform": "android",
    "weakness": "MASWE-0007",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0310",
    "title": "Runtime Use of Reused Initialization Vectors in Symmetric Encryption",
    "platform": "android",
    "weakness": "MASWE-0007",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0311",
    "title": "Insecure Random API Usage",
    "platform": "ios",
    "weakness": "MASWE-0012",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0312",
    "title": "References to Explicit Security Provider in Cryptographic APIs",
    "platform": "android",
    "weakness": "MASWE-0007",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0313",
    "title": "References to APIs for Preventing Keyboard Caching of Text Fields",
    "platform": "ios",
    "weakness": "MASWE-0036",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0314",
    "title": "Runtime Monitoring of Text Fields Eligible for Keyboard Caching",
    "platform": "ios",
    "weakness": "MASWE-0036",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0315",
    "title": "Sensitive Data Exposed via Notifications",
    "platform": "android",
    "weakness": "MASWE-0037",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0316",
    "title": "App Exposing User Authentication Data in Text Input Fields",
    "platform": "android",
    "weakness": "MASWE-0036",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0317",
    "title": "Broken Symmetric Encryption Modes",
    "platform": "ios",
    "weakness": "MASWE-0007",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0318",
    "title": "References to SDK APIs Known to Handle Sensitive User Data",
    "platform": "android",
    "weakness": "MASWE-0073",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0319",
    "title": "Runtime Use of SDK APIs Known to Handle Sensitive User Data",
    "platform": "android",
    "weakness": "MASWE-0073",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0320",
    "title": "WebViews Not Cleaning Up Sensitive Data",
    "platform": "android",
    "weakness": "MASWE-0001",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0321",
    "title": "Hardcoded HTTP URLs",
    "platform": "ios",
    "weakness": "MASWE-0026",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0322",
    "title": "App Transport Security Configurations Allowing Cleartext Traffic",
    "platform": "ios",
    "weakness": "MASWE-0026",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0323",
    "title": "Uses of Low-Level Networking APIs for Cleartext Traffic",
    "platform": "ios",
    "weakness": "MASWE-0026",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0326",
    "title": "References to APIs Allowing Fallback to Non-Biometric Authentication",
    "platform": "android",
    "weakness": "MASWE-0021",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0327",
    "title": "References to APIs for Event-Bound Biometric Authentication",
    "platform": "android",
    "weakness": "MASWE-0020",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0328",
    "title": "References to APIs Detecting Biometric Enrollment Changes",
    "platform": "android",
    "weakness": "MASWE-0022",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0329",
    "title": "References to APIs Enforcing Authentication without Explicit User Action",
    "platform": "android",
    "weakness": "MASWE-0020",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0330",
    "title": "References to APIs for Keys used in Biometric Authentication with Extended Validity Duration",
    "platform": "android",
    "weakness": "MASWE-0020",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0331",
    "title": "Use of Deprecated WebView APIs",
    "platform": "ios",
    "weakness": "MASWE-0035",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0332",
    "title": "Attacker-Controlled URI in WebViews",
    "platform": "ios",
    "weakness": "MASWE-0035",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0333",
    "title": "Overly Broad File Read Access in WebViews",
    "platform": "ios",
    "weakness": "MASWE-0034",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0334",
    "title": "Native Code Exposed Through WebViews",
    "platform": "android",
    "weakness": "MASWE-0034",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0335",
    "title": "WebView File Origin Access Relaxed by Configuration",
    "platform": "ios",
    "weakness": "MASWE-0034",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0336",
    "title": "Runtime Setting of Relaxed WebView File Origin Policies",
    "platform": "ios",
    "weakness": "MASWE-0034",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0337",
    "title": "References to Object Deserialization of Untrusted Data",
    "platform": "android",
    "weakness": "MASWE-0050",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0339",
    "title": "SQL Injection in Content Providers",
    "platform": "android",
    "weakness": "MASWE-0050",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0340",
    "title": "References to Overlay Attack Protections",
    "platform": "android",
    "weakness": "MASWE-0036",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0342",
    "title": "References to Weak ATS TLS Policy Exceptions in Info.plist",
    "platform": "ios",
    "weakness": "MASWE-0026",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0343",
    "title": "URLSession TLS Protocol Configuration",
    "platform": "ios",
    "weakness": "MASWE-0026",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0344",
    "title": "Network.framework TLS Protocol Configuration",
    "platform": "ios",
    "weakness": "MASWE-0026",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0345",
    "title": "Embedded or Third-party TLS Stack Configuration",
    "platform": "ios",
    "weakness": "MASWE-0026",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0346",
    "title": "References to APIs Hiding Sensitive Data in Text Input Fields",
    "platform": "ios",
    "weakness": "MASWE-0036",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0347",
    "title": "Runtime Use of APIs Hiding Sensitive Data in Text Input Fields",
    "platform": "ios",
    "weakness": "MASWE-0036",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0348",
    "title": "Insecure TLS Protocols in Network Traffic",
    "platform": "ios",
    "weakness": "MASWE-0026",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0349",
    "title": "Runtime Use of Insecure Random APIs",
    "platform": "ios",
    "weakness": "MASWE-0012",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0350",
    "title": "Runtime Use of Broken Symmetric Encryption Modes",
    "platform": "android",
    "weakness": "MASWE-0007",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0354",
    "title": "Runtime Use of Hook Detection Techniques",
    "platform": "ios",
    "weakness": "MASWE-0058",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0355",
    "title": "References to Unauthorized Database Access through Content Providers",
    "platform": "android",
    "weakness": "MASWE-0018",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0356",
    "title": "Runtime Verification of Unauthorized Database Access through Content Providers",
    "platform": "android",
    "weakness": "MASWE-0018",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0357",
    "title": "References to Oversharing of File-Based Content Providers",
    "platform": "android",
    "weakness": "MASWE-0018",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0358",
    "title": "Implementation Details Exposure Through Logging APIs",
    "platform": "ios",
    "weakness": "MASWE-0061",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0359",
    "title": "Implementation Details Exposure in Logs",
    "platform": "ios",
    "weakness": "MASWE-0061",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0360",
    "title": "Purpose String Accuracy for Reachable Protected Resource Access",
    "platform": "ios",
    "weakness": "MASWE-0066",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0361",
    "title": "Runtime Use of Protected Resource APIs Without Accurate Purpose Strings",
    "platform": "ios",
    "weakness": "MASWE-0066",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0362",
    "title": "Entitlements for Unjustified Capability Exposure",
    "platform": "ios",
    "weakness": "MASWE-0066",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0363",
    "title": "Runtime Use of Entitlement-Backed APIs for Unjustified Capability Exposure",
    "platform": "ios",
    "weakness": "MASWE-0066",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0364",
    "title": "Exported And Unprotected Activities That Expose Sensitive Functionality",
    "platform": "android",
    "weakness": "MASWE-0018",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0365",
    "title": "Exported And Unprotected Services That Expose Sensitive Functionality",
    "platform": "android",
    "weakness": "MASWE-0018",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0366",
    "title": "Exported And Unprotected Broadcast Receivers That Expose Sensitive Functionality",
    "platform": "android",
    "weakness": "MASWE-0018",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0367",
    "title": "Runtime Use of Virtual Device Detection Techniques",
    "platform": "ios",
    "weakness": "MASWE-0053",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0370",
    "title": "Missing Input Validation in Custom URL Scheme Handlers",
    "platform": "ios",
    "weakness": "MASWE-0029",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0371",
    "title": "Missing Source Validation in Custom URL Scheme Handlers",
    "platform": "ios",
    "weakness": "MASWE-0029",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0372",
    "title": "Implicit Intents Used for Internal App Communication",
    "platform": "android",
    "weakness": "MASWE-0032",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0374",
    "title": "References to Implicit Intents Carrying Sensitive Extras",
    "platform": "android",
    "weakness": "MASWE-0032",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0375",
    "title": "Missing Validation of Data Returned from Implicit Intents",
    "platform": "android",
    "weakness": "MASWE-0050",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0376",
    "title": "References to Native Bridge APIs in WebViews",
    "platform": "ios",
    "weakness": "MASWE-0034",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0377",
    "title": "References to `evaluateJavaScript` Used as Bridge Reply in `WKScriptMessageHandler`",
    "platform": "ios",
    "weakness": "MASWE-0034",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0378",
    "title": "References to Password Fields in WebView-Loaded HTML",
    "platform": "ios",
    "weakness": "MASWE-0034",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0379",
    "title": "References to `evaluateJavaScript` Without Content World Isolation",
    "platform": "ios",
    "weakness": "MASWE-0034",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0380",
    "title": "References to `evaluateJavaScript` Writing Sensitive Data into WebView DOM",
    "platform": "ios",
    "weakness": "MASWE-0034",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0381",
    "title": "References to Insecure PendingIntent Creation",
    "platform": "android",
    "weakness": "MASWE-0032",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0382",
    "title": "Runtime Use of Enforced Updating APIs",
    "platform": "android",
    "weakness": "MASWE-0043",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0383",
    "title": "References to Enforced Updating APIs",
    "platform": "ios",
    "weakness": "MASWE-0043",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0384",
    "title": "Runtime Use of Enforced Updating APIs",
    "platform": "ios",
    "weakness": "MASWE-0043",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0385",
    "title": "Missing Certificate Pinning in ATS",
    "platform": "ios",
    "weakness": "MASWE-0028",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0386",
    "title": "References to Object Deserialization of Untrusted Data",
    "platform": "ios",
    "weakness": "MASWE-0050",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0387",
    "title": "References to Storage Integrity Check APIs",
    "platform": "ios",
    "weakness": "MASWE-0057",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0388",
    "title": "References to Sensitive Data Stored Unprotected in Shared App Group Containers",
    "platform": "ios",
    "weakness": "MASWE-0001",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0389",
    "title": "References to the App-Wide Restriction of Custom Keyboards",
    "platform": "ios",
    "weakness": "MASWE-0031",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0390",
    "title": "Full Access Requested by a Custom Keyboard Extension",
    "platform": "ios",
    "weakness": "MASWE-0066",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0391",
    "title": "Insufficient Obfuscation of Security-Relevant Native Code",
    "platform": "ios",
    "weakness": "MASWE-0059",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0392",
    "title": "References to Enforced Updating APIs",
    "platform": "android",
    "weakness": "MASWE-0043",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0393",
    "title": "Use of Unverified App Links",
    "platform": "android",
    "weakness": "MASWE-0029",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0394",
    "title": "Missing Input Validation in Custom URL Scheme Handlers",
    "platform": "android",
    "weakness": "MASWE-0029",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0395",
    "title": "Missing Input Validation in Universal Link Handlers",
    "platform": "ios",
    "weakness": "MASWE-0029",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0396",
    "title": "References to URLSessionDelegate Bypassing Certificate Validation",
    "platform": "ios",
    "weakness": "MASWE-0027",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0397",
    "title": "References to WKNavigationDelegate Bypassing Certificate Validation",
    "platform": "ios",
    "weakness": "MASWE-0027",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0398",
    "title": "References to WebViewClient URL Loading Handlers",
    "platform": "android",
    "weakness": "MASWE-0035",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0399",
    "title": "SafeBrowsing Disabled",
    "platform": "android",
    "weakness": "MASWE-0035",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0400",
    "title": "Runtime Use of WebViewClient URL Loading Handlers",
    "platform": "android",
    "weakness": "MASWE-0035",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0401",
    "title": "References to Debugging Detection APIs",
    "platform": "ios",
    "weakness": "MASWE-0064",
    "status": "beta"
  },
  {
    "id": "MASTG-TEST-0402",
    "title": "Runtime Use of Debugging Detection APIs",
    "platform": "ios",
    "weakness": "MASWE-0064",
    "status": "beta"
  }
];
