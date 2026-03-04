import { sign, verify } from 'node:crypto';
import { encodeMultibase, decodeMultibase } from './base58';
import { createPrivateKeyObject, createPublicKeyObject } from './keygen';
import type { DataIntegrityProof } from './types';

/**
 * Deterministic JSON serialization with recursively sorted keys.
 */
function stableStringify(value: unknown): string {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(stableStringify).join(',') + ']';
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + stableStringify(obj[k])).join(',') + '}';
}

function canonicalize(obj: unknown): Buffer {
  return Buffer.from(stableStringify(obj), 'utf-8');
}

/**
 * Create a DataIntegrityProof for a document using Ed25519.
 */
export function createProof(
  document: object,
  privateKeyBytes: Uint8Array,
  verificationMethod: string,
  proofPurpose: string = 'assertionMethod'
): DataIntegrityProof {
  const canonical = canonicalize(document);
  const privateKey = createPrivateKeyObject(privateKeyBytes);
  const signature = sign(null, canonical, privateKey);
  const proofValue = encodeMultibase(new Uint8Array(signature));

  return {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-2022',
    created: new Date().toISOString(),
    verificationMethod,
    proofPurpose,
    proofValue,
  };
}

/**
 * Verify a DataIntegrityProof against a document using Ed25519.
 */
export function verifyProof(
  document: object,
  proof: DataIntegrityProof,
  publicKeyBytes: Uint8Array
): boolean {
  if (proof.type !== 'DataIntegrityProof') return false;
  if (proof.cryptosuite !== 'eddsa-2022') return false;

  try {
    // Remove proof from document for verification
    const docWithoutProof = { ...document } as Record<string, unknown>;
    delete docWithoutProof['proof'];

    const canonical = canonicalize(docWithoutProof);
    const signature = decodeMultibase(proof.proofValue);
    const publicKey = createPublicKeyObject(publicKeyBytes);

    return verify(null, canonical, publicKey, Buffer.from(signature));
  } catch {
    return false;
  }
}
