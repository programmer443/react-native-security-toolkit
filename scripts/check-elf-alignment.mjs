#!/usr/bin/env node
/**
 * Asserts that a shared library's loadable segments are 16 KB aligned.
 *
 * Android 15 runs on devices with 16 KB memory pages, and Google Play requires
 * 64-bit native code to support them. A library linked with the older 4 KB
 * assumption fails to load there — a crash on launch, not a degraded feature.
 *
 * The ELF program header is read directly rather than shelling out to
 * `llvm-readelf`, because that binary lives at a path that depends on which NDK
 * the machine happens to have installed, and a check that cannot find its own
 * tool fails in a way that looks identical to the library being misaligned.
 *
 * 32-bit ABIs are reported but not enforced: the 16 KB page size applies to
 * 64-bit devices.
 *
 * Usage: node scripts/check-elf-alignment.mjs <file.so> [...]
 */

import fs from 'node:fs/promises';
import process from 'node:process';

const REQUIRED_ALIGNMENT = 16 * 1024;
const PT_LOAD = 1;

/** Reads the alignment of every PT_LOAD segment in an ELF file. */
function loadSegmentAlignments(buffer) {
  if (buffer.length < 64 || buffer.toString('latin1', 1, 4) !== 'ELF') {
    throw new Error('not an ELF file');
  }

  const is64Bit = buffer[4] === 2;
  const isLittleEndian = buffer[5] === 1;
  if (!isLittleEndian) {
    throw new Error('big-endian ELF is not supported by this check');
  }

  const phoff = is64Bit ? Number(buffer.readBigUInt64LE(0x20)) : buffer.readUInt32LE(0x1c);
  const phentsize = buffer.readUInt16LE(is64Bit ? 0x36 : 0x2a);
  const phnum = buffer.readUInt16LE(is64Bit ? 0x38 : 0x2c);

  const alignments = [];
  for (let index = 0; index < phnum; index += 1) {
    const start = phoff + index * phentsize;
    if (start + phentsize > buffer.length) {
      throw new Error('program header table extends past the end of the file');
    }
    if (buffer.readUInt32LE(start) !== PT_LOAD) {
      continue;
    }
    alignments.push(
      is64Bit ? Number(buffer.readBigUInt64LE(start + 48)) : buffer.readUInt32LE(start + 28)
    );
  }

  return { is64Bit, alignments };
}

async function main() {
  const files = process.argv.slice(2);
  if (files.length === 0) {
    process.stderr.write('usage: node scripts/check-elf-alignment.mjs <file.so> [...]\n');
    process.exitCode = 2;
    return;
  }

  let failures = 0;

  for (const file of files) {
    let result;
    try {
      result = loadSegmentAlignments(await fs.readFile(file));
    } catch (error) {
      process.stdout.write(`  FAIL  ${file}: ${error.message}\n`);
      failures += 1;
      continue;
    }

    const { is64Bit, alignments } = result;
    const shown = alignments.map((value) => `0x${value.toString(16)}`).join(', ') || 'none';
    const width = is64Bit ? '64-bit' : '32-bit';

    if (alignments.length === 0) {
      process.stdout.write(`  FAIL  ${file} (${width}): no PT_LOAD segments\n`);
      failures += 1;
      continue;
    }

    if (!is64Bit) {
      process.stdout.write(`  skip  ${file} (${width}): LOAD alignment ${shown}, not enforced\n`);
      continue;
    }

    if (alignments.some((value) => value < REQUIRED_ALIGNMENT)) {
      process.stdout.write(
        `  FAIL  ${file} (${width}): LOAD alignment ${shown}, need at least 0x4000\n`
      );
      failures += 1;
      continue;
    }

    process.stdout.write(`  ok    ${file} (${width}): LOAD alignment ${shown}\n`);
  }

  if (failures > 0) {
    process.stdout.write(`\n${failures} library file(s) are not 16 KB aligned.\n`);
    process.exitCode = 1;
  }
}

main().catch((error) => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 2;
});
