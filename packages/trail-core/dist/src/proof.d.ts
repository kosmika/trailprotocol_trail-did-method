import type { DataIntegrityProof, SupportedCryptosuite } from './types';
/**
 * Default cryptosuite used when none is specified.
 */
export declare const DEFAULT_CRYPTOSUITE: SupportedCryptosuite;
/**
 * Check whether a cryptosuite identifier is supported by this implementation.
 */
export declare function isSupportedCryptosuite(id: string): id is SupportedCryptosuite;
/**
 * Create a DataIntegrityProof for a document using Ed25519.
 *
 * @param document - The document to sign
 * @param privateKeyBytes - Ed25519 private key (32 bytes)
 * @param verificationMethod - DID URL of the verification method (e.g. did:trail:self:z6Mk...#key-1)
 * @param proofPurpose - Proof purpose (default: assertionMethod)
 * @param cryptosuite - Cryptosuite to use (default: eddsa-jcs-2023). Enables crypto agility.
 */
export declare function createProof(document: object, privateKeyBytes: Uint8Array, verificationMethod: string, proofPurpose?: string, cryptosuite?: SupportedCryptosuite): DataIntegrityProof;
/**
 * Verify a DataIntegrityProof against a document using Ed25519.
 *
 * Supports crypto agility: verifies any proof whose cryptosuite is in the
 * SUPPORTED_CRYPTOSUITES registry and has status 'active'.
 */
export declare function verifyProof(document: object, proof: DataIntegrityProof, publicKeyBytes: Uint8Array): boolean;
