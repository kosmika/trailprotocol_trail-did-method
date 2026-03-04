import type { DidDocument, TrailKeyPair, TrailMode, ServiceEndpoint, VerificationMethod } from './types';
import { SUPPORTED_CRYPTOSUITES } from './types';

/**
 * Current TRAIL Protocol specification version.
 */
export const SPEC_VERSION = '1.1.0';

export interface CreateDocumentOptions {
  mode?: TrailMode;
  controller?: string;
  services?: ServiceEndpoint[];
  aiSystemType?: string;
  euAiActRiskClass?: string;
  parentOrganization?: string;
}

export function createDidDocument(
  did: string,
  keys: TrailKeyPair,
  options: CreateDocumentOptions = {}
): DidDocument {
  const mode = options.mode ?? detectMode(did);
  const keyId = `${did}#key-1`;

  const doc: DidDocument = {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://trailprotocol.org/ns/did/v1',
    ],
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: 'JsonWebKey2020',
        controller: options.controller ?? did,
        publicKeyJwk: keys.publicKeyJwk,
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
  };

  if (options.controller) {
    doc.controller = options.controller;
  }

  // Mode-specific properties
  doc['trail:trailMode'] = mode;

  if (mode === 'self') {
    doc['trail:trailTrustTier'] = 0;
  }

  if (mode === 'agent') {
    if (options.parentOrganization) {
      doc['trail:parentOrganization'] = options.parentOrganization;
      doc.controller = options.parentOrganization;
    }
    if (options.aiSystemType) {
      doc['trail:aiSystemType'] = options.aiSystemType;
    }
    if (options.euAiActRiskClass) {
      doc['trail:euAiActRiskClass'] = options.euAiActRiskClass;
    }
  }

  // Crypto Agility: declare supported cryptosuites
  doc['trail:supportedCryptosuites'] = SUPPORTED_CRYPTOSUITES
    .filter(s => s.status === 'active')
    .map(s => s.id);

  // Spec version
  doc['trail:specVersion'] = SPEC_VERSION;

  // Services
  const services: ServiceEndpoint[] = options.services ?? [];

  if (mode === 'org' || mode === 'agent') {
    services.push({
      id: `${did}#trail-registry`,
      type: 'TrailRegistryService',
      serviceEndpoint: `https://registry.trailprotocol.org/1.0/identifiers/${did}`,
    });
  }

  if (services.length > 0) {
    doc.service = services;
  }

  return doc;
}

/**
 * Rotate the verification key of a DID Document.
 *
 * Creates a new verification method (key-N+1) as the active key,
 * and retains the previous key with a `deactivated` timestamp in the metadata.
 * The DID itself does NOT change — only the key material rotates.
 *
 * Only applicable to org and agent mode DIDs. Self-mode DIDs derive their
 * identifier from the public key, so key rotation requires creating a new DID.
 *
 * @param doc - Existing DID Document to rotate
 * @param newKeys - New Ed25519 key pair
 * @returns Updated DID Document with rotated key + metadata about the rotation
 */
export function rotateKey(
  doc: DidDocument,
  newKeys: TrailKeyPair
): { document: DidDocument; rotationMetadata: KeyRotationMetadata } {
  const mode = doc['trail:trailMode'];
  if (mode === 'self') {
    throw new Error(
      'Key rotation is not supported for self-mode DIDs. ' +
      'Self-mode DIDs derive their identifier from the public key. ' +
      'Create a new self-mode DID instead.'
    );
  }

  const did = doc.id;
  const existingKeys = doc.verificationMethod;
  const currentKeyIndex = existingKeys.length;
  const newKeyId = `${did}#key-${currentKeyIndex + 1}`;

  const newVerificationMethod: VerificationMethod = {
    id: newKeyId,
    type: 'JsonWebKey2020',
    controller: doc.controller ?? did,
    publicKeyJwk: newKeys.publicKeyJwk,
  };

  // Previous key is kept for historical verification but removed from active lists
  const rotatedDoc: DidDocument = {
    ...doc,
    verificationMethod: [...existingKeys, newVerificationMethod],
    authentication: [newKeyId],
    assertionMethod: [newKeyId],
  };

  const rotationMetadata: KeyRotationMetadata = {
    previousKeyId: existingKeys[existingKeys.length - 1].id,
    newKeyId,
    rotatedAt: new Date().toISOString(),
    previousKeyRetained: true,
  };

  return { document: rotatedDoc, rotationMetadata };
}

export interface KeyRotationMetadata {
  previousKeyId: string;
  newKeyId: string;
  rotatedAt: string;
  previousKeyRetained: boolean;
}

function detectMode(did: string): TrailMode {
  const parts = did.split(':');
  if (parts.length < 4) return 'self';
  return (parts[2] as TrailMode) || 'self';
}
