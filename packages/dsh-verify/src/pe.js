/**
 * Read the preferred ImageBase from the PE header.
 *
 * Why it is needed: addresses inside tools like addr2line / nm are "static addresses"
 * (preferred base + RVA), while what we get at crash time is a runtime address (after ASLR).
 * Converting between the two requires the module's own preferred base.
 *
 * Deliberately duplicated in dsh-crashlab and dsh-verify: the two packages must stay
 * independently installable, and cross-package code sharing is limited to the contract
 * types. Do not hoist this into a shared module - keep the two copies in sync by hand.
 */
import { closeSync, openSync, readSync } from 'node:fs';

/**
 * @param {string} path - PE file (.exe / .dll).
 * @returns {number|undefined} preferred ImageBase, or undefined when it cannot be read.
 */
export function readPreferredImageBase(path) {
  let fd;
  try {
    fd = openSync(path, 'r');
    const dos = Buffer.alloc(64);
    readSync(fd, dos, 0, 64, 0);
    if (dos.readUInt16LE(0) !== 0x5a4d) return undefined; // 'MZ'
    const peOffset = dos.readUInt32LE(0x3c);
    if (peOffset <= 0 || peOffset > 0x1000) return undefined;

    const header = Buffer.alloc(24 + 0x70);
    readSync(fd, header, 0, header.length, peOffset);
    if (header.readUInt32LE(0) !== 0x00004550) return undefined; // 'PE\0\0'

    const optional = 24;
    const magic = header.readUInt16LE(optional);
    if (magic === 0x20b) return Number(header.readBigUInt64LE(optional + 24)); // PE32+
    if (magic === 0x10b) return header.readUInt32LE(optional + 28); // PE32
    return undefined;
  } catch {
    return undefined;
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        /* failing to close does not matter */
      }
    }
  }
}
