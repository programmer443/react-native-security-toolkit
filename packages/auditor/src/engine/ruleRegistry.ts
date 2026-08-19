import { knowledge } from '../knowledge/index.js';
import type { DiscoveredFile } from '../types/file.js';
import type { SecurityRule } from '../types/rule.js';

/**
 * The set of rules a scan will run.
 *
 * Identifiers are validated on registration rather than at review time. A rule
 * identifier is a permanent, published contract — it appears in suppression
 * files, baselines and SARIF output, and §78 requires it to stay stable forever
 * once shipped — so a typo has to fail loudly the first time it is seen.
 */

/** `RNSEC-<AREA>-<NNN>`, where area may itself be hyphenated. */
const RULE_ID_PATTERN = /^RNSEC-[A-Z0-9]+(?:-[A-Z0-9]+)*-\d{3}$/;

export class RuleRegistryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RuleRegistryError';
  }
}

export class RuleRegistry {
  private readonly byId = new Map<string, SecurityRule>();

  constructor(rules: readonly SecurityRule[] = []) {
    for (const rule of rules) {
      this.register(rule);
    }
  }

  register(rule: SecurityRule): void {
    if (!RULE_ID_PATTERN.test(rule.id)) {
      throw new RuleRegistryError(
        `Rule identifier "${rule.id}" does not match RNSEC-<AREA>-<NNN>, e.g. RNSEC-STORAGE-001.`
      );
    }
    if (this.byId.has(rule.id)) {
      throw new RuleRegistryError(
        `Rule identifier "${rule.id}" is registered twice. Identifiers are permanent and unique.`
      );
    }

    // A fabricated standards reference must fail here, not in a report. Every
    // identifier is checked against the committed knowledge snapshot, which is
    // generated from the official sources rather than typed from memory (§32).
    const unknown = knowledge.unknownReferences(rule.knowledge);
    if (unknown.length > 0) {
      throw new RuleRegistryError(
        `Rule "${rule.id}" cites ${unknown.join(', ')}, which ${unknown.length === 1 ? 'is' : 'are'} ` +
          `absent from knowledge snapshot ${knowledge.version}. Standards references must be real: ` +
          `re-run "pnpm knowledge:sync" if the identifier is newer than the snapshot, or remove it.`
      );
    }
    this.byId.set(rule.id, rule);
  }

  get rules(): readonly SecurityRule[] {
    return [...this.byId.values()];
  }

  get(id: string): SecurityRule | undefined {
    return this.byId.get(id);
  }

  /**
   * Rules applicable to one file.
   *
   * An empty `languages` or `fileKinds` list means "any", which is what a
   * text-scanning rule such as secret detection needs. Selecting here rather
   * than inside each rule is what lets the engine skip reading a file no rule
   * cares about.
   */
  rulesFor(file: DiscoveredFile, disabledRules: readonly string[] = []): readonly SecurityRule[] {
    const disabled = new Set(disabledRules);
    return this.rules.filter((rule) => {
      if (disabled.has(rule.id)) {
        return false;
      }
      if (rule.languages.length > 0 && !rule.languages.includes(file.language)) {
        return false;
      }
      if (rule.fileKinds.length > 0 && !rule.fileKinds.includes(file.kind)) {
        return false;
      }
      if (rule.excludeFileKinds?.includes(file.kind) === true) {
        return false;
      }
      return true;
    });
  }
}

export { builtinRules } from '../rules/index.js';
