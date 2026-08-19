import fs from 'node:fs/promises';
import path from 'node:path';

import { classifyFile } from '../classification/classify.js';
import { hasBinaryExtension } from './binary.js';
import { isDirectoryExcluded, matchesAnyGlob } from '../util/glob.js';
import { isWithinRoot, toProjectPath } from '../util/paths.js';
import type { DiscoveredFile, SkippedPath } from '../types/file.js';
import type { ScanLimits } from '../types/config.js';

/**
 * File discovery over a repository that is assumed to be hostile (§44).
 *
 * The threats this pass exists to contain are all mundane and all real:
 *
 * - **Symbolic links are never followed.** A link to `/` turns a scan into a
 *   walk of the whole filesystem; a link back up the tree turns it into an
 *   infinite one; a link to `~/.ssh/id_rsa` turns a secrets scanner into an
 *   exfiltration tool the moment its report is uploaded to CI. Links are skipped
 *   and recorded, never resolved.
 * - **Every limit is a recorded event.** Hitting the file cap sets `truncated`
 *   and names the path where the scan stopped. A scanner that quietly stops at
 *   ten thousand files reports "no findings" for everything after them.
 * - **Depth is bounded.** Generated trees and pathological nesting are ordinary
 *   in mobile projects.
 * - **Binary files are not read.** By extension here, and by content sniffing at
 *   read time.
 *
 * The walk is iterative rather than recursive: a deep tree must produce a
 * recorded limit, not a stack overflow.
 */

export interface DiscoveryOptions {
  /** Absolute path of the project root. */
  readonly root: string;
  /** Glob patterns to include. Empty means everything not excluded. */
  readonly include: readonly string[];
  readonly exclude: readonly string[];
  readonly limits: ScanLimits;
}

export interface DiscoveryResult {
  readonly files: readonly DiscoveredFile[];
  /**
   * Paths skipped for a reason that indicates a hazard or a limit.
   *
   * Configuration-driven skips are counted rather than listed: a project that
   * excluded `node_modules` does not need forty thousand lines telling it so,
   * whereas an unreadable directory or an exhausted budget is something a
   * developer must see.
   */
  readonly skipped: readonly SkippedPath[];
  /** True when a limit stopped the walk before the project was fully traversed. */
  readonly truncated: boolean;
  readonly totalBytes: number;
  readonly excludedCount: number;
  readonly notIncludedCount: number;
}

export async function discoverFiles(options: DiscoveryOptions): Promise<DiscoveryResult> {
  const root = path.resolve(options.root);
  const { include, exclude, limits } = options;

  const files: DiscoveredFile[] = [];
  const skipped: SkippedPath[] = [];
  let totalBytes = 0;
  let truncated = false;
  let excludedCount = 0;
  let notIncludedCount = 0;

  const queue: Array<{ absolutePath: string; depth: number }> = [{ absolutePath: root, depth: 0 }];

  while (queue.length > 0) {
    const current = queue.shift();
    if (current === undefined) {
      break;
    }

    let entries;
    try {
      entries = await fs.readdir(current.absolutePath, { withFileTypes: true });
    } catch (error: unknown) {
      skipped.push({
        path: toProjectPath(root, current.absolutePath) || '.',
        reason: 'unreadable',
        detail: describeError(error),
      });
      continue;
    }

    // Sorted so a report is identical between runs and between machines.
    entries.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));

    for (const entry of entries) {
      const absolutePath = path.join(current.absolutePath, entry.name);
      const relativePath = toProjectPath(root, absolutePath);

      // A path that resolves outside the root cannot be part of the project,
      // however it got here.
      if (!isWithinRoot(root, absolutePath)) {
        skipped.push({ path: relativePath, reason: 'outside-project-root' });
        continue;
      }

      if (entry.isSymbolicLink()) {
        skipped.push({
          path: relativePath,
          reason: 'symbolic-link',
          detail: 'symbolic links are never followed',
        });
        continue;
      }

      if (entry.isDirectory()) {
        if (isDirectoryExcluded(relativePath, exclude)) {
          excludedCount += 1;
          continue;
        }
        if (current.depth + 1 > limits.maxDepth) {
          skipped.push({
            path: relativePath,
            reason: 'depth-limit-reached',
            detail: `directory nesting exceeded ${limits.maxDepth}`,
          });
          truncated = true;
          continue;
        }
        queue.push({ absolutePath, depth: current.depth + 1 });
        continue;
      }

      if (!entry.isFile()) {
        // Sockets, FIFOs and device nodes. Reading one can block forever.
        skipped.push({ path: relativePath, reason: 'unreadable', detail: 'not a regular file' });
        continue;
      }

      if (matchesAnyGlob(relativePath, exclude)) {
        excludedCount += 1;
        continue;
      }

      if (include.length > 0 && !matchesAnyGlob(relativePath, include)) {
        notIncludedCount += 1;
        continue;
      }

      if (hasBinaryExtension(relativePath)) {
        skipped.push({ path: relativePath, reason: 'binary', detail: 'binary file extension' });
        continue;
      }

      if (files.length >= limits.maxFiles) {
        skipped.push({
          path: relativePath,
          reason: 'file-limit-reached',
          detail: `stopped after ${limits.maxFiles} files`,
        });
        truncated = true;
        return finish();
      }

      let sizeBytes: number;
      try {
        sizeBytes = (await fs.stat(absolutePath)).size;
      } catch (error: unknown) {
        skipped.push({ path: relativePath, reason: 'unreadable', detail: describeError(error) });
        continue;
      }

      if (sizeBytes > limits.maxFileBytes) {
        skipped.push({
          path: relativePath,
          reason: 'too-large',
          detail: `${sizeBytes} bytes exceeds the ${limits.maxFileBytes} byte limit`,
        });
        continue;
      }

      if (totalBytes + sizeBytes > limits.maxTotalBytes) {
        skipped.push({
          path: relativePath,
          reason: 'total-size-limit-reached',
          detail: `stopped after ${totalBytes} bytes`,
        });
        truncated = true;
        return finish();
      }

      totalBytes += sizeBytes;
      const { language, kind } = classifyFile(relativePath);
      files.push({ absolutePath, path: relativePath, sizeBytes, language, kind });
    }
  }

  return finish();

  function finish(): DiscoveryResult {
    files.sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
    return { files, skipped, truncated, totalBytes, excludedCount, notIncludedCount };
  }
}

function describeError(error: unknown): string {
  if (error instanceof Error) {
    const code = (error as NodeJS.ErrnoException).code;
    return code ?? error.message;
  }
  return String(error);
}
