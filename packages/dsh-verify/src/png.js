/**
 * Minimal PNG decoding + pixel diff.
 *
 * Why hand-rolled: `verify_assert_screenshot` compares pixels, and the design rules
 * out third-party dependencies and a vision MCP. PNG's compression layer is plain
 * zlib (bundled with Node); the only parts to write by hand are chunk parsing and
 * undoing the five row filters.
 *
 * Supports: bit depth 8, color type 0/2/4/6, non-interlaced. Anything else is
 * reported as an error rather than guessed.
 */
import { readFileSync } from 'node:fs';
import { inflateSync } from 'node:zlib';

const SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

const CHANNELS = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 };

function paeth(left, up, upLeft) {
  const estimate = left + up - upLeft;
  const toLeft = Math.abs(estimate - left);
  const toUp = Math.abs(estimate - up);
  const toUpLeft = Math.abs(estimate - upLeft);
  if (toLeft <= toUp && toLeft <= toUpLeft) return left;
  return toUp <= toUpLeft ? up : upLeft;
}

/**
 * Decode a PNG.
 * @param {string} path
 * @returns {{width: number, height: number, data: Buffer}} RGBA pixels
 */
export function decodePng(path) {
  const buffer = readFileSync(path);
  if (buffer.length < 8 || !buffer.subarray(0, 8).equals(SIGNATURE)) throw new Error(`${path} is not a PNG`);

  let offset = 8;
  let header;
  const idat = [];
  while (offset + 8 <= buffer.length) {
    const length = buffer.readUInt32BE(offset);
    const type = buffer.toString('ascii', offset + 4, offset + 8);
    const data = buffer.subarray(offset + 8, offset + 8 + length);
    offset += 12 + length;
    if (type === 'IHDR') {
      header = {
        width: data.readUInt32BE(0),
        height: data.readUInt32BE(4),
        bitDepth: data[8],
        colorType: data[9],
        interlace: data[12],
      };
    } else if (type === 'IDAT') {
      idat.push(Buffer.from(data));
    } else if (type === 'IEND') {
      break;
    }
  }
  if (!header) throw new Error(`${path} has no IHDR`);
  if (header.bitDepth !== 8) throw new Error(`${path} has bit depth ${header.bitDepth}, only 8 is supported`);
  if (header.interlace !== 0) throw new Error(`${path} is an interlaced PNG, which is not supported`);
  const channels = CHANNELS[header.colorType];
  if (!channels) throw new Error(`${path} has unsupported color type ${header.colorType}`);
  if (idat.length === 0) throw new Error(`${path} has no IDAT`);

  const raw = inflateSync(Buffer.concat(idat));
  const stride = header.width * channels;
  const pixels = Buffer.alloc(stride * header.height);
  let source = 0;
  for (let row = 0; row < header.height; row += 1) {
    const filter = raw[source];
    source += 1;
    const line = raw.subarray(source, source + stride);
    source += stride;
    const out = pixels.subarray(row * stride, (row + 1) * stride);
    const prior = row > 0 ? pixels.subarray((row - 1) * stride, row * stride) : null;
    for (let index = 0; index < stride; index += 1) {
      const left = index >= channels ? out[index - channels] : 0;
      const up = prior ? prior[index] : 0;
      const upLeft = prior && index >= channels ? prior[index - channels] : 0;
      const value = line[index];
      switch (filter) {
        case 0:
          out[index] = value;
          break;
        case 1:
          out[index] = (value + left) & 0xff;
          break;
        case 2:
          out[index] = (value + up) & 0xff;
          break;
        case 3:
          out[index] = (value + ((left + up) >> 1)) & 0xff;
          break;
        case 4:
          out[index] = (value + paeth(left, up, upLeft)) & 0xff;
          break;
        default:
          throw new Error(`${path} has unknown filter ${filter} on row ${row}`);
      }
    }
  }

  // Normalize to RGBA so comparison needs no branching.
  const rgba = Buffer.alloc(header.width * header.height * 4);
  for (let pixel = 0; pixel < header.width * header.height; pixel += 1) {
    const from = pixel * channels;
    const to = pixel * 4;
    if (channels === 1) {
      rgba[to] = pixels[from];
      rgba[to + 1] = pixels[from];
      rgba[to + 2] = pixels[from];
      rgba[to + 3] = 255;
    } else if (channels === 2) {
      rgba[to] = pixels[from];
      rgba[to + 1] = pixels[from];
      rgba[to + 2] = pixels[from];
      rgba[to + 3] = pixels[from + 1];
    } else if (channels === 3) {
      rgba[to] = pixels[from];
      rgba[to + 1] = pixels[from + 1];
      rgba[to + 2] = pixels[from + 2];
      rgba[to + 3] = 255;
    } else {
      rgba[to] = pixels[from];
      rgba[to + 1] = pixels[from + 1];
      rgba[to + 2] = pixels[from + 2];
      rgba[to + 3] = pixels[from + 3];
    }
  }

  return { width: header.width, height: header.height, data: rgba };
}

/**
 * Pixel difference between two PNGs.
 * @param {string} actualPath
 * @param {string} expectedPath
 * @param {number} tolerance - per-channel delta allowed (0 = strict equality)
 */
export function diffPng(actualPath, expectedPath, tolerance = 0) {
  const actual = decodePng(actualPath);
  const expected = decodePng(expectedPath);
  if (actual.width !== expected.width || actual.height !== expected.height) {
    return {
      size_mismatch: true,
      actual: { width: actual.width, height: actual.height },
      expected: { width: expected.width, height: expected.height },
      differing: actual.width * actual.height,
      total: actual.width * actual.height,
      ratio: 1,
    };
  }
  const total = actual.width * actual.height;
  let differing = 0;
  for (let pixel = 0; pixel < total; pixel += 1) {
    const at = pixel * 4;
    const delta = Math.max(
      Math.abs(actual.data[at] - expected.data[at]),
      Math.abs(actual.data[at + 1] - expected.data[at + 1]),
      Math.abs(actual.data[at + 2] - expected.data[at + 2]),
      Math.abs(actual.data[at + 3] - expected.data[at + 3]),
    );
    if (delta > tolerance) differing += 1;
  }
  return {
    size_mismatch: false,
    actual: { width: actual.width, height: actual.height },
    expected: { width: expected.width, height: expected.height },
    differing,
    total,
    ratio: total === 0 ? 0 : differing / total,
  };
}
