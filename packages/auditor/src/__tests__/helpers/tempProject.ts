import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/**
 * Builds throwaway projects on disk for tests.
 *
 * The auditor's contract is about *repositories*, and a repository is a shape on
 * a filesystem: symbolic links, unreadable directories, files that are enormous
 * or binary or both. None of that can be committed to this repository as a
 * fixture — a symlink loop and a 4 MB file are not things to keep in git — so
 * hostile projects are built here, used, and deleted.
 */
export class TempProject {
  readonly root: string;

  private constructor(root: string) {
    this.root = root;
  }

  static create(prefix = 'rnsec-audit-'): TempProject {
    return new TempProject(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  }

  /** Writes a file, creating parent directories. */
  file(relativePath: string, contents: string | Buffer): this {
    const absolute = path.join(this.root, relativePath);
    fs.mkdirSync(path.dirname(absolute), { recursive: true });
    fs.writeFileSync(absolute, contents);
    return this;
  }

  dir(relativePath: string): this {
    fs.mkdirSync(path.join(this.root, relativePath), { recursive: true });
    return this;
  }

  /** Creates a symbolic link. Targets may point anywhere, including outside the project. */
  symlink(relativePath: string, target: string): this {
    const absolute = path.join(this.root, relativePath);
    fs.mkdirSync(path.dirname(absolute), { recursive: true });
    fs.symlinkSync(target, absolute);
    return this;
  }

  path(relativePath: string): string {
    return path.join(this.root, relativePath);
  }

  exists(relativePath: string): boolean {
    return fs.existsSync(this.path(relativePath));
  }

  remove(): void {
    fs.rmSync(this.root, { recursive: true, force: true });
  }
}
