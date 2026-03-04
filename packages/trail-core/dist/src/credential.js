"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createSelfSignedCredential = createSelfSignedCredential;
exports.verifyCredential = verifyCredential;
const proof_1 = require("./proof");
/**
 * Create a self-signed Verifiable Credential.
 * Self-signed VCs carry Trust Tier 0 (cryptographic proof only, no third-party verification).
 */
function createSelfSignedCredential(issuerDid, subjectDid, claims, privateKeyBytes) {
    const vc = {
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
    const proof = (0, proof_1.createProof)(vc, privateKeyBytes, `${issuerDid}#key-1`, 'assertionMethod');
    return { ...vc, proof };
}
/**
 * Verify a Verifiable Credential's proof and structure.
 */
function verifyCredential(vc, publicKeyBytes) {
    const errors = [];
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
    const proofValid = (0, proof_1.verifyProof)(vc, vc.proof, publicKeyBytes);
    if (!proofValid) {
        errors.push('Proof verification failed: signature invalid');
    }
    return {
        valid: errors.length === 0,
        errors,
    };
}
