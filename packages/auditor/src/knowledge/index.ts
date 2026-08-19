import { snapshot } from './snapshots/2026-1/index.js';
import type {
  CweEntry,
  KnowledgeSnapshot,
  MastgTest,
  MasvsControl,
  MasweWeakness,
} from './types.js';
import type { StandardReference } from '../types/finding.js';
import type { KnowledgeRefs } from '../types/rule.js';

/**
 * The versioned security knowledge layer.
 *
 * Two jobs, both of them about honesty rather than convenience:
 *
 * 1. **Nothing is invented.** Every identifier a report can contain exists in a
 *    snapshot generated from the official sources by `scripts/sync-knowledge.mjs`
 *    — never typed from memory. `MASWE-0104` looks exactly as plausible as
 *    `MASWE-0004`, and only one of them is real.
 * 2. **A fabricated identifier fails loudly.** Rules are validated when they are
 *    registered, so a bad reference is a startup error rather than a line in a
 *    report that a reader has no way to check.
 *
 * Mappings live here rather than in rule code (§33): a rule declares identifiers
 * and nothing else, and no prose from any standard is copied into this package.
 */

export type {
  CweEntry,
  KnowledgeSnapshot,
  MastgTest,
  MasvsControl,
  MasweWeakness,
} from './types.js';

/** How sure a rule is that a mapping is right. Absent means `medium`. */
export type MappingConfidence = 'low' | 'medium' | 'high';

const DEFAULT_MAPPING_CONFIDENCE: MappingConfidence = 'medium';

/** Resolved references, with the titles a report needs. */
export interface ResolvedKnowledge {
  readonly cwe?: readonly StandardReference[];
  readonly masvs?: readonly StandardReference[];
  readonly maswe?: readonly StandardReference[];
  readonly mastg?: readonly StandardReference[];
}

/** Indexed access to one snapshot. */
export class KnowledgeIndex {
  private readonly cweById: ReadonlyMap<string, CweEntry>;
  private readonly masvsById: ReadonlyMap<string, MasvsControl>;
  private readonly masweById: ReadonlyMap<string, MasweWeakness>;
  private readonly mastgById: ReadonlyMap<string, MastgTest>;
  private readonly mastgByWeakness: ReadonlyMap<string, readonly MastgTest[]>;

  constructor(private readonly data: KnowledgeSnapshot) {
    this.cweById = new Map(data.cwe.map((entry) => [entry.id, entry]));
    this.masvsById = new Map(data.masvs.map((entry) => [entry.id, entry]));
    this.masweById = new Map(data.maswe.map((entry) => [entry.id, entry]));
    this.mastgById = new Map(data.mastg.map((entry) => [entry.id, entry]));

    const byWeakness = new Map<string, MastgTest[]>();
    for (const test of data.mastg) {
      if (test.weakness === '') {
        continue;
      }
      const existing = byWeakness.get(test.weakness);
      if (existing === undefined) {
        byWeakness.set(test.weakness, [test]);
      } else {
        existing.push(test);
      }
    }
    this.mastgByWeakness = byWeakness;
  }

  /** Snapshot version, e.g. `2026.1`. Reported alongside findings that cite it. */
  get version(): string {
    return this.data.version;
  }

  get counts(): { cwe: number; masvs: number; maswe: number; mastg: number } {
    return {
      cwe: this.data.cwe.length,
      masvs: this.data.masvs.length,
      maswe: this.data.maswe.length,
      mastg: this.data.mastg.length,
    };
  }

  cwe(id: string): CweEntry | undefined {
    return this.cweById.get(id);
  }

  masvs(id: string): MasvsControl | undefined {
    return this.masvsById.get(id);
  }

  maswe(id: string): MasweWeakness | undefined {
    return this.masweById.get(id);
  }

  mastg(id: string): MastgTest | undefined {
    return this.mastgById.get(id);
  }

  /**
   * MASTG tests that verify a weakness.
   *
   * This is what lets a report answer "how can the fix be verified?" with a real
   * test identifier instead of a paragraph of advice (§40).
   */
  mastgTestsFor(masweId: string): readonly MastgTest[] {
    return this.mastgByWeakness.get(masweId) ?? [];
  }

  /**
   * Identifiers in `refs` that are absent from this snapshot.
   *
   * An empty array means every reference is real. Anything else is a fabricated
   * or stale identifier, and the caller is expected to treat it as an error.
   */
  unknownReferences(refs: KnowledgeRefs): readonly string[] {
    const unknown: string[] = [];
    for (const id of refs.cwe ?? []) {
      if (!this.cweById.has(id)) {
        unknown.push(id);
      }
    }
    for (const id of refs.masvs ?? []) {
      if (!this.masvsById.has(id)) {
        unknown.push(id);
      }
    }
    for (const id of refs.maswe ?? []) {
      if (!this.masweById.has(id)) {
        unknown.push(id);
      }
    }
    for (const id of refs.mastg ?? []) {
      if (!this.mastgById.has(id)) {
        unknown.push(id);
      }
    }
    return unknown;
  }

  /**
   * Turns declared identifiers into report-ready references.
   *
   * Unknown identifiers are **dropped rather than passed through**. Registration
   * has already rejected them loudly; if one reaches here anyway, a report with a
   * missing reference is far better than one citing a standard that does not
   * exist.
   */
  resolve(refs: KnowledgeRefs | undefined): ResolvedKnowledge {
    if (refs === undefined) {
      return {};
    }
    const confidence = refs.mappingConfidence ?? DEFAULT_MAPPING_CONFIDENCE;

    const cwe = build(refs.cwe, (id) => this.cweById.get(id)?.name, confidence);
    const masvs = build(refs.masvs, (id) => this.masvsById.get(id)?.title, confidence);
    const maswe = build(refs.maswe, (id) => this.masweById.get(id)?.title, confidence);
    const mastg = build(refs.mastg, (id) => this.mastgById.get(id)?.title, confidence);

    return {
      ...(cwe === undefined ? {} : { cwe }),
      ...(masvs === undefined ? {} : { masvs }),
      ...(maswe === undefined ? {} : { maswe }),
      ...(mastg === undefined ? {} : { mastg }),
    };
  }
}

function build(
  ids: readonly string[] | undefined,
  lookup: (id: string) => string | undefined,
  mappingConfidence: MappingConfidence
): readonly StandardReference[] | undefined {
  if (ids === undefined || ids.length === 0) {
    return undefined;
  }
  const references: StandardReference[] = [];
  for (const id of ids) {
    const title = lookup(id);
    if (title === undefined) {
      continue;
    }
    references.push({ id, title, mappingConfidence });
  }
  return references.length === 0 ? undefined : references;
}

/** The snapshot this build ships. */
export const knowledge = new KnowledgeIndex(snapshot);
