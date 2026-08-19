/**
 * `@rn-security/auditor` — static security analysis for React Native projects.
 *
 * Developer and CI tooling. **Nothing here belongs in a mobile application
 * bundle** (§45): it reads source, parses it and reports on it, and it is a
 * separate package precisely so an app that only wants runtime checks never
 * installs a parser.
 *
 * The repository under analysis is treated as hostile throughout (§44). No file
 * from it is ever executed, imported, evaluated or installed — including its
 * configuration file, which is parsed and statically evaluated rather than
 * loaded.
 *
 * Rules ship separately, in Phase 6. Today the engine runs whatever rules it is
 * given, which is also how it is tested.
 */

export { auditProject } from './engine/auditProject.js';
export type { AuditOptions } from './engine/auditProject.js';

export { RuleRegistry, RuleRegistryError, builtinRules } from './engine/ruleRegistry.js';

/**
 * The versioned standards knowledge this build ships, and the index over it.
 *
 * Exported because a consumer of a report needs the same lookup the engine used:
 * identifier to official title, weakness to the MASTG tests that verify it.
 */
export { KnowledgeIndex, knowledge } from './knowledge/index.js';
export type {
  CweEntry,
  KnowledgeSnapshot,
  MappingConfidence,
  MastgTest,
  MasvsControl,
  MasweWeakness,
  ResolvedKnowledge,
} from './knowledge/index.js';
export { createFingerprint } from './engine/fingerprint.js';
export type { FingerprintInput } from './engine/fingerprint.js';
export { deduplicateFindings } from './engine/dedupe.js';
export {
  compareSeverity,
  maxSeverity,
  meetsThreshold,
  resolveSeverity,
} from './engine/severity.js';
export { SuppressionIndex, scanInlineDirectives } from './engine/suppression.js';
export type { InlineDirective, SuppressionError } from './engine/suppression.js';

export {
  consoleReporter,
  getReporter,
  htmlReporter,
  jsonReporter,
  markdownReporter,
  reportFormats,
  reporters,
  sarifReporter,
} from './reporting/index.js';
export type { ReportFormat, ReportOptions, Reporter } from './reporting/index.js';

export { discoverFiles } from './discovery/discoverFiles.js';
export type { DiscoveryOptions, DiscoveryResult } from './discovery/discoverFiles.js';
export { hasBinaryExtension, looksBinary } from './discovery/binary.js';

export {
  classifyFile,
  fileKindOf,
  isExamplePath,
  isFixturePath,
  isTestPath,
  languageOf,
} from './classification/classify.js';

export { clearParseCache, isParsableLanguage, parseJavaScript } from './parsers/javascript.js';

export { findConfigFile, loadConfig } from './config/loadConfig.js';
export type { LoadedConfig } from './config/loadConfig.js';
export { AuditorConfigError, resolveConfig } from './config/resolveConfig.js';
export { DEFAULT_EXCLUDE, defaultConfig, defaultLimits } from './config/defaults.js';
export { StaticEvaluationError } from './config/staticEvaluate.js';

export { matchesAnyGlob, matchesGlob } from './util/glob.js';

/**
 * Analysis helpers, exported because a consumer building its own checks needs
 * the same primitives the rules use — in particular an XML and property-list
 * scanner that never resolves an entity.
 */
export { elementsNamed, scanPlist, scanXml } from './analysis/xml.js';

/**
 * Project readiness for the on-device runtime checks — static analysis of what a
 * project declares, never a device check.
 */
export { analyseRuntimeReadiness } from './runtimeReadiness.js';
export type { RuntimeReadiness } from './runtimeReadiness.js';
export type { PlistEntry, XmlElement } from './analysis/xml.js';
export { isSensitiveName, sensitiveKindOf } from './analysis/sensitivity.js';
export { looksHighEntropy, shannonEntropy } from './analysis/entropy.js';

export type {
  AuditReport,
  AuditStats,
  RuleError,
  SuppressedFindingReport,
  SuppressionErrorReport,
} from './types/report.js';

export type {
  AuditorConfig,
  AuditorOptions,
  Category,
  Confidence,
  DiscoveredFile,
  FileKind,
  FindingLocation,
  FindingSource,
  JavaScriptParse,
  KnowledgeRefs,
  Language,
  ParsedFile,
  ProjectContext,
  RawFinding,
  RuleContext,
  RuleOverride,
  ScanLimits,
  SecurityEvidence,
  SecurityFinding,
  SecurityReference,
  SecurityRule,
  Severity,
  SkipReason,
  SkippedPath,
  StandardReference,
  SuppressionEntry,
  UnparsedFile,
} from './types/index.js';
