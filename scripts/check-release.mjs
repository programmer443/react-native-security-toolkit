#!/usr/bin/env node
/**
 * Release preflight.
 *
 * Everything here is a mistake that is cheap to make and expensive to undo: npm
 * publishes are immutable, and an unpublish window of 72 hours is not a plan.
 * A wrong version, a missing licence, a package that ships its tests or forgets
 * its entry point — each of those is permanent once it is on the registry.
 *
 * Usage:
 *   node scripts/check-release.mjs            # check the current versions
 *   node scripts/check-release.mjs v0.1.0     # also require they match this tag
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PACKAGES = ['runtime', 'auditor', 'cli', 'mcp'];

const problems = [];
const notes = [];

function fail(message) {
  problems.push(message);
}

function note(message) {
  notes.push(message);
}

async function readJson(file) {
  return JSON.parse(await fs.readFile(file, 'utf8'));
}

async function exists(file) {
  try {
    await fs.access(file);
    return true;
  } catch {
    return false;
  }
}

async function main() {
  const tag = process.argv[2];
  const manifests = [];

  for (const name of PACKAGES) {
    const directory = path.join(root, 'packages', name);
    const manifest = await readJson(path.join(directory, 'package.json'));
    manifests.push({ name, directory, manifest });

    // Files npm shows on the package page. A package without them looks
    // abandoned before anyone reads a line of it.
    for (const required of ['README.md', 'LICENSE']) {
      if (!(await exists(path.join(directory, required)))) {
        fail(`${manifest.name}: missing ${required}`);
      }
    }

    for (const field of ['description', 'license', 'repository', 'homepage', 'bugs', 'author']) {
      if (manifest[field] === undefined) {
        fail(`${manifest.name}: package.json has no "${field}"`);
      }
    }

    if (manifest.private === true) {
      fail(`${manifest.name}: marked private, so it cannot be published`);
    }

    if (manifest.publishConfig?.provenance !== true) {
      fail(`${manifest.name}: publishConfig.provenance is not true`);
    }

    if (manifest.name.startsWith('@') && manifest.publishConfig?.access !== 'public') {
      fail(`${manifest.name}: scoped package without publishConfig.access "public"`);
    }

    // A dependency on an unpublished workspace package would resolve to nothing
    // for a consumer. pnpm rewrites `workspace:*` at publish time; anything else
    // pointing inside this repository would not be rewritten.
    for (const [dependency, range] of Object.entries(manifest.dependencies ?? {})) {
      if (typeof range === 'string' && range.startsWith('file:')) {
        fail(`${manifest.name}: dependency ${dependency} uses a file: range`);
      }
    }

    const bin = manifest.bin;
    if (bin !== undefined) {
      for (const [command, target] of Object.entries(bin)) {
        if (!(await exists(path.join(directory, target)))) {
          fail(`${manifest.name}: bin "${command}" points at ${target}, which does not exist`);
        }
      }
    }
  }

  // Every package moves together. Independent versions are defensible, but this
  // project has not decided to carry that complexity, and a silent divergence is
  // how a consumer ends up with a CLI that cannot load its own engine.
  const versions = new Set(manifests.map((entry) => entry.manifest.version));
  if (versions.size !== 1) {
    fail(
      `packages disagree on version: ${manifests
        .map((entry) => `${entry.manifest.name}@${entry.manifest.version}`)
        .join(', ')}`
    );
  }

  const version = manifests[0]?.manifest.version ?? '0.0.0';

  if (tag !== undefined) {
    const expected = `v${version}`;
    if (tag !== expected) {
      fail(`tag ${tag} does not match the package version (expected ${expected})`);
    }
  }

  const changelog = await fs.readFile(path.join(root, 'CHANGELOG.md'), 'utf8');
  if (!changelog.includes(`## [${version}]`)) {
    fail(`CHANGELOG.md has no "## [${version}]" section`);
  }

  // Pre-1.0 is a statement about stability, not a defect — but it should be a
  // deliberate one.
  if (version.startsWith('0.')) {
    note(`version ${version} is pre-1.0: breaking changes are allowed in minor releases`);
  }

  process.stdout.write(`Release preflight for v${version}\n\n`);
  for (const message of notes) {
    process.stdout.write(`  note  ${message}\n`);
  }
  for (const message of problems) {
    process.stdout.write(`  FAIL  ${message}\n`);
  }

  if (problems.length === 0) {
    process.stdout.write(`\n${PACKAGES.length} package(s) ready to publish.\n`);
    return;
  }

  process.stdout.write(`\n${problems.length} problem(s). Nothing was published.\n`);
  process.exitCode = 1;
}

main().catch((error) => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 2;
});
