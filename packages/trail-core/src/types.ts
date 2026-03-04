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
}

export interface DidResolutionResult {
  didDocument: DidDocument;
  didDocumentMetadata: Record<string, unknown>;
  didResolutionMetadata: Record<string, unknown>;
}

export interface DataIntegrityProof {
  type: 'DataIntegrityProof';
  cryptosuite: 'eddsa-2022';
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue: string;
}

export interface VerifiableCredential {
  '@context': string[];
  type: string[];
  issuer: string;
  issuanceDate: string;
  credentialSubject: Record<string, unknown>;
  proof?: DataIntegrityProof;
}
