#!/usr/bin/env node
/**
 * Regenerates the security knowledge snapshot from official upstream sources.
 *
 * §32 forbids fabricated identifiers, and hand-authoring hundreds of
 * MASVS/MASWE/MASTG/CWE references is exactly how fabrication happens. So none of
 * them are hand-authored: this script downloads the standards, extracts their
 * identifiers, and writes generated TypeScript modules that are committed to the
 * repository.
 *
 * Committed **and** generated is deliberate. Committed, because a security scan
 * must work offline and produce the same report in six months. Generated,
 * because the moment a human types `MASWE-0104` from memory, the project has
 * started inventing standards references.
 *
 * Sources:
 *   MASVS  github.com/OWASP/masvs       OWASP_MASVS.yaml
 *   MASWE  github.com/OWASP/maswe       weaknesses/**\/MASWE-*.md front matter
 *   MASTG  github.com/OWASP/mastg       tests/**, tests-beta/** front matter
 *   CWE    cwe.mitre.org                one definition page per referenced entry
 *
 * Usage:
 *   node scripts/sync-knowledge.mjs [--version 2026.1] [--out src/knowledge/snapshots]
 *
 * The script writes nothing outside its output directory and executes nothing it
 * downloads.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import zlib from 'node:zlib';
import { promisify } from 'node:util';

const gunzip = promisify(zlib.gunzip);

const REPOSITORIES = {
  masvs: { owner: 'OWASP', repo: 'masvs', branch: 'master' },
  maswe: { owner: 'OWASP', repo: 'maswe', branch: 'main' },
  mastg: { owner: 'OWASP', repo: 'mastg', branch: 'master' },
};

const CWE_DEFINITION_URL = (id) => `https://cwe.mitre.org/data/definitions/${id}.html`;

/** Extra CWE identifiers to resolve even when no MASWE entry references them. */
const ADDITIONAL_CWE = [
  79, 94, 95, 200, 259, 276, 295, 297, 311, 312, 319, 327, 328, 330, 338, 359, 489, 502, 532, 547,
  749, 757, 798, 921, 926, 927, 939, 940, 1004, 1104, 1204, 1426, 1427,
];

const USER_AGENT =
  'rn-security-toolkit-knowledge-sync (+https://github.com/programmer443/react-native-security-toolkit)';

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const outputDirectory = path.resolve(options.out, options.version.replace('.', '-'));

  log(`Snapshot ${options.version} -> ${outputDirectory}`);

  const sources = {};
  const archives = {};
  for (const [key, repository] of Object.entries(REPOSITORIES)) {
    const commit = await resolveCommit(repository);
    log(`${repository.owner}/${repository.repo}@${commit.sha.slice(0, 10)} (${commit.date})`);
    archives[key] = await downloadRepositoryFiles(repository, commit.sha);
    sources[key] = { ...repository, ...commit };
  }

  const masvs = extractMasvs(archives.masvs);
  log(`MASVS: ${masvs.length} controls`);

  const maswe = extractMaswe(archives.maswe);
  log(`MASWE: ${maswe.length} weaknesses`);

  const mastg = extractMastg(archives.mastg);
  log(`MASTG: ${mastg.length} tests`);

  const cweIds = new Set(ADDITIONAL_CWE);
  for (const weakness of maswe) {
    for (const id of weakness.cwe) {
      cweIds.add(Number(id.replace('CWE-', '')));
    }
  }
  const cwe = await resolveCweNames([...cweIds].sort((left, right) => left - right));
  log(`CWE: ${cwe.entries.length} entries (catalogue ${cwe.catalogueVersion})`);

  await fs.mkdir(outputDirectory, { recursive: true });
  await writeModule(outputDirectory, 'masvs', 'MasvsControl', masvs);
  await writeModule(outputDirectory, 'maswe', 'MasweWeakness', maswe);
  await writeModule(outputDirectory, 'mastg', 'MastgTest', mastg);
  await writeModule(outputDirectory, 'cwe', 'CweEntry', cwe.entries);
  await writeIndex(outputDirectory, options.version);
  await writeSources(outputDirectory, options.version, sources, cwe.catalogueVersion, {
    masvs: masvs.length,
    maswe: maswe.length,
    mastg: mastg.length,
    cwe: cwe.entries.length,
  });

  log('Done. Review the diff before committing: this is standards data, not code.');
}

function parseArguments(argv) {
  const options = { version: '2026.1', out: 'src/knowledge/snapshots' };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === '--version') {
      options.version = argv[index + 1] ?? options.version;
      index += 1;
    } else if (flag === '--out') {
      options.out = argv[index + 1] ?? options.out;
      index += 1;
    }
  }
  return options;
}

function log(message) {
  process.stdout.write(`${message}\n`);
}

async function fetchWithRetry(url, { asBuffer = false, attempts = 3 } = {}) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await fetch(url, { headers: { 'user-agent': USER_AGENT } });
      if (!response.ok) {
        throw new Error(`${response.status} ${response.statusText}`);
      }
      return asBuffer ? Buffer.from(await response.arrayBuffer()) : await response.text();
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 500 * attempt));
    }
  }
  throw new Error(`Failed to fetch ${url}: ${lastError?.message ?? 'unknown error'}`);
}

/** Pins the snapshot to an exact commit, so a regeneration is reproducible. */
async function resolveCommit({ owner, repo, branch }) {
  const body = await fetchWithRetry(
    `https://api.github.com/repos/${owner}/${repo}/commits/${branch}`
  );
  const commit = JSON.parse(body);
  return { sha: commit.sha, date: commit.commit?.committer?.date ?? 'unknown' };
}

/**
 * Downloads one repository as a tarball and returns its text files.
 *
 * One request per repository rather than several hundred, and — more to the
 * point — the archive is only ever *read*. Nothing is extracted to disk, so a
 * malicious path inside the archive has nowhere to land.
 */
async function downloadRepositoryFiles({ owner, repo }, sha) {
  const archive = await fetchWithRetry(
    `https://codeload.github.com/${owner}/${repo}/tar.gz/${sha}`,
    {
      asBuffer: true,
    }
  );
  const tar = await gunzip(archive);
  return readTar(tar);
}

/**
 * Minimal reader for the POSIX tar format GitHub produces.
 *
 * 512-byte header blocks, name at offset 0, size (octal) at 124, type flag at
 * 156, followed by the file contents padded to a 512-byte boundary. Only regular
 * files under a size cap are returned; everything else — links, devices,
 * directories — is skipped rather than interpreted.
 */
function readTar(buffer) {
  const files = new Map();
  const MAX_ENTRY_BYTES = 4 * 1024 * 1024;
  let offset = 0;

  while (offset + 512 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 512);
    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '');
    if (name === '') {
      offset += 512;
      continue;
    }

    const sizeField = header.subarray(124, 136).toString('utf8').replace(/\0.*$/, '').trim();
    const size = Number.parseInt(sizeField, 8);
    const typeFlag = header.subarray(156, 157).toString('utf8');
    const contentStart = offset + 512;

    if (!Number.isFinite(size) || size < 0) {
      break;
    }

    if ((typeFlag === '0' || typeFlag === '\0') && size <= MAX_ENTRY_BYTES) {
      // Strip the `repo-sha/` prefix GitHub adds to every entry.
      const relative = name.split('/').slice(1).join('/');
      files.set(relative, buffer.subarray(contentStart, contentStart + size).toString('utf8'));
    }

    offset = contentStart + Math.ceil(size / 512) * 512;
  }

  return files;
}

/**
 * Reads YAML front matter.
 *
 * A deliberately small parser for the shape these documents actually use:
 * `key: value`, `key: [a, b]`, and one level of nested mapping. It is not a YAML
 * implementation and does not pretend to be — every value it produces is
 * validated against an identifier pattern before it reaches the snapshot, so a
 * misparse becomes a dropped entry rather than an invented one.
 */
function parseFrontMatter(text) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (match === null) {
    return null;
  }

  const result = {};
  let currentParent = null;

  for (const rawLine of match[1].split(/\r?\n/)) {
    if (rawLine.trim() === '' || rawLine.trimStart().startsWith('#')) {
      continue;
    }

    const indented = /^\s{2,}\S/.test(rawLine);
    const line = rawLine.trim();
    const separator = line.indexOf(':');
    if (separator === -1) {
      continue;
    }

    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();

    if (indented && currentParent !== null) {
      result[currentParent][key] = parseScalar(value);
      continue;
    }

    if (value === '') {
      result[key] = {};
      currentParent = key;
      continue;
    }

    result[key] = parseScalar(value);
    currentParent = null;
  }

  return result;
}

function parseScalar(value) {
  if (value.startsWith('[') && value.endsWith(']')) {
    return value
      .slice(1, -1)
      .split(',')
      .map((entry) => entry.trim().replace(/^["']|["']$/g, ''))
      .filter((entry) => entry !== '');
  }
  return value.replace(/^["']|["']$/g, '');
}

/** Extracts MASVS controls from `OWASP_MASVS.yaml`. */
function extractMasvs(files) {
  const yaml = files.get('OWASP_MASVS.yaml');
  if (yaml === undefined) {
    throw new Error('OWASP_MASVS.yaml not found in the MASVS repository');
  }

  const controls = [];
  let group = null;
  let groupTitle = null;

  for (const line of yaml.split(/\r?\n/)) {
    const groupMatch = /^- id:\s*(MASVS-[A-Z]+)\s*$/.exec(line);
    if (groupMatch !== null) {
      group = groupMatch[1];
      groupTitle = null;
      continue;
    }
    if (group !== null && groupTitle === null) {
      const titleMatch = /^\s{2}title:\s*(.+?)\s*$/.exec(line);
      if (titleMatch !== null) {
        groupTitle = titleMatch[1];
        continue;
      }
    }
    const controlMatch = /^\s*-\s*id:\s*(MASVS-[A-Z]+-\d+)\s*$/.exec(line);
    if (controlMatch !== null) {
      controls.push({
        id: controlMatch[1],
        group: group ?? '',
        groupTitle: groupTitle ?? '',
        title: '',
      });
      continue;
    }
    const statementMatch = /^\s*statement:\s*(.+?)\s*$/.exec(line);
    if (statementMatch !== null && controls.length > 0) {
      const last = controls[controls.length - 1];
      if (last.title === '') {
        last.title = statementMatch[1].replace(/^["']|["']$/g, '');
      }
    }
  }

  const valid = controls.filter(
    (control) => /^MASVS-[A-Z]+-\d+$/.test(control.id) && control.title !== ''
  );
  if (valid.length === 0) {
    throw new Error('No MASVS controls were parsed; the upstream format has changed');
  }
  return valid.sort((left, right) => left.id.localeCompare(right.id));
}

/** Extracts MASWE weaknesses and the mappings they declare. */
function extractMaswe(files) {
  const weaknesses = [];

  for (const [filePath, contents] of files) {
    if (!/^weaknesses\/.*\/MASWE-\d+\.md$/.test(filePath)) {
      continue;
    }
    const front = parseFrontMatter(contents);
    if (front === null || typeof front.id !== 'string' || !/^MASWE-\d{4}$/.test(front.id)) {
      continue;
    }

    const mappings =
      typeof front.mappings === 'object' && front.mappings !== null ? front.mappings : {};
    weaknesses.push({
      id: front.id,
      title: typeof front.title === 'string' ? front.title : front.id,
      masvs: asArray(mappings['masvs-v2']).filter((entry) => /^MASVS-[A-Z]+-\d+$/.test(entry)),
      cwe: asArray(mappings.cwe)
        .map((entry) => `CWE-${String(entry).replace(/[^0-9]/g, '')}`)
        .filter((entry) => /^CWE-\d+$/.test(entry)),
      platforms: asArray(front.platform).filter((entry) => entry === 'android' || entry === 'ios'),
    });
  }

  if (weaknesses.length === 0) {
    throw new Error('No MASWE weaknesses were parsed; the upstream format has changed');
  }
  return weaknesses.sort((left, right) => left.id.localeCompare(right.id));
}

/** Extracts MASTG test identifiers and the weakness each verifies. */
function extractMastg(files) {
  const tests = [];

  for (const [filePath, contents] of files) {
    if (!/^tests(-beta)?\/.*\/MASTG-TEST-\d+\.md$/.test(filePath)) {
      continue;
    }
    const front = parseFrontMatter(contents);
    if (front === null || typeof front.id !== 'string' || !/^MASTG-TEST-\d{4}$/.test(front.id)) {
      continue;
    }

    tests.push({
      id: front.id,
      title: typeof front.title === 'string' ? front.title : front.id,
      platform: typeof front.platform === 'string' ? front.platform : 'generic',
      weakness:
        typeof front.weakness === 'string' && /^MASWE-\d{4}$/.test(front.weakness)
          ? front.weakness
          : '',
      status: filePath.startsWith('tests-beta/') ? 'beta' : 'stable',
    });
  }

  if (tests.length === 0) {
    throw new Error('No MASTG tests were parsed; the upstream format has changed');
  }
  return tests.sort((left, right) => left.id.localeCompare(right.id));
}

function asArray(value) {
  if (Array.isArray(value)) {
    return value.map(String);
  }
  if (typeof value === 'string' && value !== '') {
    return [value];
  }
  return [];
}

/**
 * Resolves CWE names from MITRE, one definition page per identifier.
 *
 * The page title carries both the official name and the catalogue version, which
 * is recorded in `SOURCES.md` so a reader can tell which edition of CWE a
 * snapshot was built against.
 */
async function resolveCweNames(ids) {
  const entries = [];
  const concurrency = 4;
  let cursor = 0;
  let catalogueVersion = 'unknown';

  async function worker() {
    for (;;) {
      const index = cursor;
      cursor += 1;
      if (index >= ids.length) {
        return;
      }
      const id = ids[index];
      try {
        const html = await fetchWithRetry(CWE_DEFINITION_URL(id));
        // The name itself may contain parentheses and quotes — CWE-79 is
        // "Improper Neutralization ... ('Cross-site Scripting')" — so the
        // catalogue version is anchored at the end rather than at the first
        // bracket.
        const match =
          /<title>\s*CWE\s*-\s*CWE-(\d+):\s*([\s\S]*?)\s*\(([0-9][0-9.]*)\)\s*<\/title>/.exec(html);
        if (match === null || match[1] !== String(id)) {
          log(`  ! CWE-${id}: no name found upstream; omitted from the snapshot`);
          continue;
        }
        catalogueVersion = match[3];
        entries.push({ id: `CWE-${id}`, name: match[2].trim() });
      } catch (error) {
        log(`  ! CWE-${id}: ${error.message}; omitted from the snapshot`);
      }
    }
  }

  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  entries.sort((left, right) => Number(left.id.slice(4)) - Number(right.id.slice(4)));
  return { entries, catalogueVersion };
}

const GENERATED_HEADER = `/**
 * GENERATED FILE - DO NOT EDIT.
 *
 * Regenerate with \`pnpm --filter @rn-security/auditor knowledge:sync\`.
 * Provenance for this snapshot is recorded in SOURCES.md.
 */
`;

async function writeModule(directory, name, typeName, entries) {
  const contents = `${GENERATED_HEADER}
import type { ${typeName} } from '../../types.js';

export const ${name}: readonly ${typeName}[] = ${JSON.stringify(entries, null, 2)};
`;
  await fs.writeFile(path.join(directory, `${name}.ts`), contents, 'utf8');
}

async function writeIndex(directory, version) {
  const contents = `${GENERATED_HEADER}
import type { KnowledgeSnapshot } from '../../types.js';

import { cwe } from './cwe.js';
import { mastg } from './mastg.js';
import { masvs } from './masvs.js';
import { maswe } from './maswe.js';

export const snapshot: KnowledgeSnapshot = {
  version: '${version}',
  cwe,
  masvs,
  maswe,
  mastg,
};
`;
  await fs.writeFile(path.join(directory, 'index.ts'), contents, 'utf8');
}

async function writeSources(directory, version, sources, cweCatalogueVersion, counts) {
  const retrieved = new Date().toISOString().slice(0, 10);
  const rows = Object.entries(sources)
    .map(
      ([key, source]) =>
        `| ${key.toUpperCase()} | https://github.com/${source.owner}/${source.repo} | \`${source.sha}\` | ${source.date.slice(0, 10)} | ${counts[key]} |`
    )
    .join('\n');

  const contents = `# Knowledge snapshot ${version}

Generated by \`scripts/sync-knowledge.mjs\` on ${retrieved}. **Do not edit the snapshot by hand.**

| Standard | Source | Commit | Upstream date | Entries |
| -------- | ------ | ------ | ------------- | ------- |
${rows}
| CWE | https://cwe.mitre.org/data/definitions/ | catalogue ${cweCatalogueVersion} | ${retrieved} | ${counts.cwe} |

## What is captured

- **MASVS** — control identifiers, their group, and the control statement.
- **MASWE** — weakness identifiers, titles, and the MASVS and CWE mappings each weakness declares
  upstream.
- **MASTG** — test identifiers, titles, platform, and the weakness each test verifies. Tests under
  \`tests-beta/\` are marked \`beta\` because upstream may still renumber them.
- **CWE** — identifier and official name, for every entry referenced by a MASWE weakness or by a
  rule in this package.

Only identifiers, titles and mappings are captured. **No prose from the standards is copied**, so
this snapshot is a lookup table rather than a redistribution.

## Why it is committed

A security scan has to work offline and produce the same report months later. A snapshot that is
fetched at scan time would make reports depend on the network, and on whatever upstream looked like
that morning.
`;
  await fs.writeFile(path.join(directory, 'SOURCES.md'), contents, 'utf8');
}

main().catch((error) => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
