import { buildFinding, evidence } from '../../analysis/findings.js';
import type { RawFinding } from '../../types/finding.js';
import type { KnowledgeRefs, RuleContext, SecurityRule } from '../../types/rule.js';

/**
 * RNSEC-DEPS-001 — a dependency the build cannot pin down.
 *
 * This is deliberately **not** a vulnerability scanner. §38 asks for pluggable
 * vulnerability databases and warns against embedding an obsolete one in the
 * package; a snapshot of advisories baked into a release is stale the week it
 * ships. What this rule reports instead is what a manifest can tell you on its
 * own: dependencies whose *resolution* is not deterministic or not
 * authenticated.
 *
 * - `*` and `latest` — the build takes whatever the registry serves that day. A
 *   compromised release is picked up automatically, and two builds of the same
 *   commit are not the same application.
 * - `git://` and `http://` sources — fetched without transport authentication.
 * - A git dependency without a commit pin — the branch can be rewritten after
 *   review.
 *
 * A caret or tilde range is *not* reported. Ranges plus a committed lockfile are
 * how the ecosystem works, and flagging them would be noise.
 */

const KNOWLEDGE: KnowledgeRefs = {
  cwe: ['CWE-1104'],
  masvs: ['MASVS-CODE-3'],
  maswe: ['MASWE-0044'],
  mappingConfidence: 'medium',
};

const DEPENDENCY_FIELDS: readonly string[] = [
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies',
];

interface DependencyIssue {
  readonly id: string;
  readonly title: string;
  readonly detail: string;
  readonly severity: RawFinding['severity'];
  readonly confidence: RawFinding['confidence'];
  readonly remediation: string;
}

export const untrustedDependencyRule: SecurityRule = {
  id: 'RNSEC-DEPS-001',
  name: 'Dependency resolved from an unpinned or unauthenticated source',
  description:
    'A dependency specifier lets the build resolve to different code over time, or fetches code ' +
    'over a channel with no transport authentication.',
  severity: 'medium',
  categories: ['dependencies', 'configuration'],
  languages: ['json'],
  fileKinds: ['package-manifest'],
  knowledge: KNOWLEDGE,

  detect(context: RuleContext): readonly RawFinding[] {
    let manifest: unknown;
    try {
      manifest = JSON.parse(context.text);
    } catch {
      // A manifest that is not valid JSON is a build problem, not a security
      // finding, and something else in the toolchain will complain about it.
      return [];
    }

    if (typeof manifest !== 'object' || manifest === null || Array.isArray(manifest)) {
      return [];
    }

    const findings: RawFinding[] = [];
    const record = manifest as Record<string, unknown>;

    for (const field of DEPENDENCY_FIELDS) {
      const section = record[field];
      if (typeof section !== 'object' || section === null || Array.isArray(section)) {
        continue;
      }

      for (const [name, specifier] of Object.entries(section as Record<string, unknown>)) {
        if (typeof specifier !== 'string') {
          continue;
        }
        const issue = classify(name, specifier, field);
        if (issue === undefined) {
          continue;
        }

        const line = lineOfSpecifier(context.lines, name, specifier);
        findings.push(
          buildFinding({
            ruleId: 'RNSEC-DEPS-001',
            title: issue.title,
            description: issue.detail,
            severity: issue.severity,
            confidence: issue.confidence,
            categories: ['dependencies', 'configuration'],
            path: context.file.path,
            ...(line === undefined ? {} : { line }),
            evidence: [
              evidence('dependency-specifier', `"${name}": "${specifier}" in ${field}`, {
                ...(line === undefined ? {} : { line }),
              }),
            ],
            impact:
              'The application ships whatever that dependency resolved to at build time. An ' +
              'unpinned or unauthenticated dependency is a direct path for third-party code into ' +
              'the binary, with the privileges of the application.',
            exploitability:
              'Requires compromising the package, the account that publishes it, or — for ' +
              'unauthenticated transports — the network path to it. Supply-chain attacks of exactly ' +
              'this shape are routine.',
            remediation: issue.remediation,
            structuralContext: `${field}:${name}`,
            knowledge: KNOWLEDGE,
          })
        );
      }
    }

    return findings;
  },
};

function classify(name: string, specifier: string, field: string): DependencyIssue | undefined {
  const value = specifier.trim();

  // Peer dependencies are a compatibility statement, not something the build
  // resolves, so a wildcard there is normal.
  if ((value === '*' || value === 'latest' || value === '') && field !== 'peerDependencies') {
    return {
      id: 'unpinned',
      title: `"${name}" is not pinned to a version`,
      detail:
        `The specifier "${specifier}" resolves to whatever the registry serves at install time, so ` +
        'two builds of the same commit can contain different code.',
      severity: 'medium',
      confidence: 'high',
      remediation:
        'Pin to a semantic version range and commit a lockfile. Install with a frozen lockfile in ' +
        'CI so the build fails rather than silently drifting.',
    };
  }

  if (/^(?:git\+)?(?:git|http):\/\//.test(value)) {
    return {
      id: 'insecure-transport',
      title: `"${name}" is fetched over an unauthenticated transport`,
      detail:
        `The specifier "${specifier}" uses a protocol with no transport authentication, so the code ` +
        'that arrives can be substituted by anything on the network path.',
      severity: 'high',
      confidence: 'high',
      remediation: 'Fetch over HTTPS or SSH, and pin the dependency to a commit hash.',
    };
  }

  if (
    /^(?:git\+ssh|git\+https|github:|gitlab:|bitbucket:)/.test(value) &&
    !/#[0-9a-f]{7,40}$/i.test(value)
  ) {
    return {
      id: 'unpinned-git',
      title: `"${name}" is a git dependency without a commit pin`,
      detail:
        `The specifier "${specifier}" resolves to a branch or tag, either of which can be moved ` +
        'after review.',
      severity: 'medium',
      confidence: 'medium',
      remediation:
        'Pin the dependency to a full commit hash, or publish the package to a registry and depend ' +
        'on a version.',
    };
  }

  if (value.startsWith('http://')) {
    return {
      id: 'insecure-tarball',
      title: `"${name}" is downloaded over cleartext HTTP`,
      detail: `The specifier "${specifier}" fetches a tarball over HTTP, which can be replaced in transit.`,
      severity: 'high',
      confidence: 'high',
      remediation:
        'Use an HTTPS URL, and prefer a registry version with an integrity hash in the lockfile.',
    };
  }

  return undefined;
}

/** Finds the manifest line declaring a dependency, for a useful report location. */
function lineOfSpecifier(
  lines: readonly string[],
  name: string,
  specifier: string
): number | undefined {
  const needle = `"${name}"`;
  for (let index = 0; index < lines.length; index += 1) {
    const text = lines[index] ?? '';
    if (text.includes(needle) && text.includes(specifier)) {
      return index + 1;
    }
  }
  return undefined;
}
