import { createProof, verifyProof } from './proof';
import type { VerifiableCredential, DataIntegrityProof } from './types';

/**
 * Create a self-signed Verifiable Credential.
 * Self-signed VCs carry Trust Tier 0 (cryptographic proof only, no third-party verification).
 */
export function createSelfSignedCredential(
  issuerDid: string,
  subjectDid: string,
  claims: Record<string, unknown>,
  privateKeyBytes: Uint8Array
): VerifiableCredential {
  const vc: VerifiableCredential = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://trailprotocol.org/ns/credentials/v1',
    ],
    type: ['VerifiableCredential', 'TrailIdentityCredential'],
    issuer: issuerDid,
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id: subjectDid,
      trailTrustTier: 0,
      ...claims,
    },
  };

  const proof = createProof(
    vc,
    privateKeyBytes,
    `${issuerDid}#key-1`,
    'assertionMethod'
  );

  return { ...vc, proof };
}

export interface VerificationResult {
  valid: boolean;
  errors: string[];
}

/**
 * Verify a Verifiable Credential's proof and structure.
 */
export function verifyCredential(
  vc: VerifiableCredential,
  publicKeyBytes: Uint8Array
): VerificationResult {
  const errors: string[] = [];

  // Check required fields
  if (!vc['@context'] || !Array.isArray(vc['@context'])) {
    errors.push('Missing or invalid @context');
  }
  if (!vc.type || !Array.isArray(vc.type)) {
    errors.push('Missing or invalid type');
  }
  if (!vc.type?.includes('VerifiableCredential')) {
    errors.push('type must include VerifiableCredential');
  }
  if (!vc.issuer) {
    errors.push('Missing issuer');
  }
  if (!vc.issuanceDate) {
    errors.push('Missing issuanceDate');
  }
  if (!vc.credentialSubject) {
    errors.push('Missing credentialSubject');
  }

  // Check proof
  if (!vc.proof) {
    errors.push('Missing proof');
    return { valid: false, errors };
  }

  const proofValid = verifyProof(vc, vc.proof as DataIntegrityProof, publicKeyBytes);
  if (!proofValid) {
    errors.push('Proof verification failed: signature invalid');
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}
