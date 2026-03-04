const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE = BigInt(58);

export function encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  // Count leading zeros
  let zeros = 0;
  for (const b of bytes) {
    if (b !== 0) break;
    zeros++;
  }

  // Convert to big integer
  let num = BigInt(0);
  for (const b of bytes) {
    num = num * BigInt(256) + BigInt(b);
  }

  // Convert to base58
  let result = '';
  while (num > BigInt(0)) {
    const remainder = Number(num % BASE);
    num = num / BASE;
    result = ALPHABET[remainder] + result;
  }

  // Add leading '1's for each leading zero byte
  return '1'.repeat(zeros) + result;
}

export function decode(str: string): Uint8Array {
  if (str.length === 0) return new Uint8Array(0);

  // Count leading '1's
  let zeros = 0;
  for (const c of str) {
    if (c !== '1') break;
    zeros++;
  }

  // Convert from base58
  let num = BigInt(0);
  for (const c of str) {
    const index = ALPHABET.indexOf(c);
    if (index === -1) throw new Error(`Invalid base58 character: ${c}`);
    num = num * BASE + BigInt(index);
  }

  // Convert to bytes
  const hex = num === BigInt(0) ? '' : num.toString(16).padStart(2, '0');
  const paddedHex = hex.length % 2 ? '0' + hex : hex;
  const byteArray = [];
  for (let i = 0; i < paddedHex.length; i += 2) {
    byteArray.push(parseInt(paddedHex.substring(i, i + 2), 16));
  }

  // Prepend leading zero bytes
  const result = new Uint8Array(zeros + byteArray.length);
  result.set(new Uint8Array(byteArray), zeros);
  return result;
}

export function encodeMultibase(bytes: Uint8Array): string {
  return 'z' + encode(bytes);
}

export function decodeMultibase(multibase: string): Uint8Array {
  if (!multibase.startsWith('z')) {
    throw new Error('Only base58btc multibase (z prefix) is supported');
  }
  return decode(multibase.slice(1));
}
