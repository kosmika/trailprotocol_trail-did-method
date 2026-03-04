export interface TrailKeyPair {
    publicKeyBytes: Uint8Array;
    privateKeyBytes: Uint8Array;
    publicKeyJwk: JsonWebKey;
    publicKeyMultibase: string;
}
export type TrailMode = 'org' | 'agent' | 'self';
export interface VerificationMethod {
    id: string;
    type: string;
    controller: string;
    publicKeyJwk: JsonWebKey;
}
export interface ServiceEndpoint {
    id: string;
    type: string;
    serviceEndpoint: string;
}
export interface RecoveryPolicy {
    type: string;
    threshold?: number;
    contacts?: string[];
}
export interface DidDocument {
    '@context': string[];
    id: string;
    controller?: string;
    verificationMethod: VerificationMethod[];
    authentication: string[];
    assertionMethod: string[];
    service?: ServiceEndpoint[];
    'trail:aiSystemType'?: string;
    'trail:euAiActRiskClass'?: string;
    'trail:parentOrganization'?: string;
    'trail:trailMode'?: string;
    'trail:trailTrustTier'?: number;
    'trail:recoveryPolicy'?: RecoveryPolicy;
    'trail:specVersion'?: string;
    'trail:supportedCryptosuites'?: string[];
}
export interface DidResolutionResult {
    didDocument: DidDocument;
    didDocumentMetadata: Record<string, unknown>;
    didResolutionMetadata: Record<string, unknown>;
}
/**
 * Supported cryptosuites for DataIntegrityProof.
 * Currently only eddsa-jcs-2023 is implemented; this type enables crypto agility
 * by allowing future suites to be added without breaking changes.
 */
export type SupportedCryptosuite = 'eddsa-jcs-2023';
export interface DataIntegrityProof {
    type: 'DataIntegrityProof';
    cryptosuite: string;
    created: string;
    verificationMethod: string;
    proofPurpose: string;
    proofValue: string;
}
/**
 * Registry of supported cryptosuites and their metadata.
 * Used for crypto agility: implementations MUST support at least eddsa-jcs-2023,
 * and MAY support additional suites listed here.
 */
export declare const SUPPORTED_CRYPTOSUITES: ReadonlyArray<{
    id: SupportedCryptosuite;
    algorithm: string;
    canonicalization: string;
    keyType: string;
    status: 'active' | 'deprecated';
}>;
export interface VerifiableCredential {
    '@context': string[];
    type: string[];
    issuer: string;
    issuanceDate: string;
    credentialSubject: Record<string, unknown>;
    proof?: DataIntegrityProof;
}
