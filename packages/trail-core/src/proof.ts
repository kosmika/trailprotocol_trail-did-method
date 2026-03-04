import { sign, verify } from 'node:crypto';
import { encodeMultibase, decodeMultibase } from './base58';
import { createPrivateKeyObject, createPublicKeyObject } from './keygen';
import { jcsCanonicalizeToBuffer } from './jcs';
import type { DataIntegrityProof, SupportedCryptosuite } from './types';
import { SUPPORTED_CRYPTOSUITES } from './types';

/**
 * Default cryptosuite used when none is specified.
 */
export const DEFAULT_CRYPTOSUITE: SupportedCryptosuite = 'eddsa-jcs-2023';

/**
 * Check whether a cryptosuite identifier is supported by this implementation.
 */
export function isSupportedCryptosuite(id: string): id is SupportedCryptosuite {
  return SUPPORTED_CRYPTOSUITES.some(s => s.id === id && s.status === 'active');
}

/**
 * Create a DataIntegrityProof for a document using Ed25519.
 *
 * @param document - The document to sign
 * @param privateKeyBytes - Ed25519 private key (32 bytes)
 * @param verificationMethod - DID URL of the verification method (e.g. did:trail:self:z6Mk...#key-1)
 * @param proofPurpose - Proof purpose (default: assertionMethod)
 * @param cryptosuite - Cryptosuite to use (default: eddsa-jcs-2023). Enables crypto agility.
 */
export function createProof(
  document: object,
  privateKeyBytes: Uint8Array,
  verificationMethod: string,
  proofPurpose: string = 'assertionMethod',
  cryptosuite: SupportedCryptosuite = DEFAULT_CRYPTOSUITE
): DataIntegrityProof {
  if (!isSupportedCryptosuite(cryptosuite)) {
    throw new Error(
      `Unsupported cryptosuite: "${cryptosuite}". ` +
      `Supported: ${SUPPORTED_CRYPTOSUITES.filter(s => s.status === 'active').map(s => s.id).join(', ')}`
    );
  }

  const canonical = jcsCanonicalizeToBuffer(document);
  const privateKey = createPrivateKeyObject(privateKeyBytes);
  const signature = sign(null, canonical, privateKey);
  const proofValue = encodeMultibase(new Uint8Array(signature));

  return {
    type: 'DataIntegrityProof',
    cryptosuite,
    created: new Date().toISOString(),
    verificationMethod,
    proofPurpose,
    proofValue,
  };
}

/**
 * Verify a DataIntegrityProof against a document using Ed25519.
 *
 * Supports crypto agility: verifies any proof whose cryptosuite is in the
 * SUPPORTED_CRYPTOSUITES registry and has status 'active'.
 */
export function verifyProof(
  document: object,
  proof: DataIntegrityProof,
  publicKeyBytes: Uint8Array
): boolean {
  if (proof.type !== 'DataIntegrityProof') return false;
  if (!isSupportedCryptosuite(proof.cryptosuite)) return false;

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
