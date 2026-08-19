import path from 'node:path';

/**
 * Path handling for a hostile repository.
 *
 * Two invariants hold everywhere in the auditor:
 * 1. Paths that leave this module are **project-relative and POSIX-separated**,
 *    so a report generated on Windows reads the same as one from CI.
 * 2. No absolute path from the scanned project is ever trusted to be inside the
 *    project. Symbolic links, `..` segments and unicode tricks all produce paths
 *    that look local and are not.
 */

/** Converts an absolute path to the project-relative POSIX form used in reports. */
export function toProjectPath(root: string, absolutePath: string): string {
  const relative = path.relative(root, absolutePath);
  return relative.split(path.sep).join('/');
}

/**
 * Whether an absolute path is genuinely inside the project root.
 *
 * The trailing-separator comparison is the point: `/tmp/project-secrets` starts
 * with `/tmp/project` as a string, and a prefix check without it would accept a
 * sibling directory as part of the project.
 */
export function isWithinRoot(root: string, absolutePath: string): boolean {
  const resolvedRoot = path.resolve(root);
  const resolvedPath = path.resolve(absolutePath);
  if (resolvedPath === resolvedRoot) {
    return true;
  }
  return resolvedPath.startsWith(resolvedRoot + path.sep);
}
