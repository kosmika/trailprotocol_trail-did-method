import { sign, verify } from 'node:crypto';
import { encodeMultibase, decodeMultibase } from './base58';
import { createPrivateKeyObject, createPublicKeyObject } from './keygen';
import { jcsCanonicalizeToBuffer } from './jcs';
import type { DataIntegrityProof } from './types';

/**
 * Create a DataIntegrityProof for a document using Ed25519.
 */
export function createProof(
  document: object,
  privateKeyBytes: Uint8Array,
  verificationMethod: string,
  proofPurpose: string = 'assertionMethod'
): DataIntegrityProof {
  const canonical = jcsCanonicalizeToBuffer(document);
  const privateKey = createPrivateKeyObject(privateKeyBytes);
  const signature = sign(null, canonical, privateKey);
  const proofValue = encodeMultibase(new Uint8Array(signature));

  return {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2023',
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
  if (proof.cryptosuite !== 'eddsa-jcs-2023') return false;

  try {
    // Remove proof from document for verification
    const docWithoutProof = { ...document } as Record<string, unknown>;
    delete docWithoutProof['proof'];

    const canonical = jcsCanonicalizeToBuffer(docWithoutProof);
    const signature = decodeMultibase(proof.proofValue);
    const publicKey = createPublicKeyObject(publicKeyBytes);

    return verify(null, canonical, publicKey, Buffer.from(signature));
  } catch {
    return false;
  }
}
