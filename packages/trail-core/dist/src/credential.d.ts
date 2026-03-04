import type { VerifiableCredential } from './types';
/**
 * Create a self-signed Verifiable Credential.
 * Self-signed VCs carry Trust Tier 0 (cryptographic proof only, no third-party verification).
 */
export declare function createSelfSignedCredential(issuerDid: string, subjectDid: string, claims: Record<string, unknown>, privateKeyBytes: Uint8Array): VerifiableCredential;
export interface VerificationResult {
    valid: boolean;
    errors: string[];
}
/**
 * Verify a Verifiable Credential's proof and structure.
 */
export declare function verifyCredential(vc: VerifiableCredential, publicKeyBytes: Uint8Array): VerificationResult;
