import { generateKeyPairSync, KeyObject } from 'node:crypto';
import { encodeMultibase } from './base58';
import type { TrailKeyPair } from './types';

export function generateKeyPair(): TrailKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');

  const publicKeyBytes = extractRawPublicKey(publicKey);
  const privateKeyBytes = extractRawPrivateKey(privateKey);

  const publicKeyJwk: JsonWebKey = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: Buffer.from(publicKeyBytes).toString('base64url'),
  };

  const publicKeyMultibase = encodeMultibase(publicKeyBytes);

  return {
    publicKeyBytes,
    privateKeyBytes,
    publicKeyJwk,
    publicKeyMultibase,
  };
}

function extractRawPublicKey(key: KeyObject): Uint8Array {
  // DER-encoded Ed25519 public key: 12-byte header + 32-byte key
  const der = key.export({ type: 'spki', format: 'der' });
  return new Uint8Array(der.subarray(der.length - 32));
}

function extractRawPrivateKey(key: KeyObject): Uint8Array {
  // DER-encoded Ed25519 private key: contains 32-byte seed
  const der = key.export({ type: 'pkcs8', format: 'der' });
  // The seed is the last 32 bytes of the PKCS#8 structure (after the 16-byte header)
  return new Uint8Array(der.subarray(der.length - 32));
}

export function publicKeyFromMultibase(multibase: string): Uint8Array {
  const { decodeMultibase } = require('./base58');
  return decodeMultibase(multibase);
}

export function createPrivateKeyObject(privateKeyBytes: Uint8Array): KeyObject {
  const { createPrivateKey } = require('node:crypto');
  // Build PKCS#8 DER for Ed25519: fixed 16-byte prefix + 32-byte seed
  const pkcs8Prefix = Buffer.from([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
  ]);
  const der = Buffer.concat([pkcs8Prefix, Buffer.from(privateKeyBytes)]);
  return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}

export function createPublicKeyObject(publicKeyBytes: Uint8Array): KeyObject {
  const { createPublicKey } = require('node:crypto');
  // Build SPKI DER for Ed25519: fixed 12-byte prefix + 32-byte key
  const spkiPrefix = Buffer.from([
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
    0x70, 0x03, 0x21, 0x00,
  ]);
  const der = Buffer.concat([spkiPrefix, Buffer.from(publicKeyBytes)]);
  return createPublicKey({ key: der, format: 'der', type: 'spki' });
}
