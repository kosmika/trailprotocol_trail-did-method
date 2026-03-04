import type { DidDocument, TrailKeyPair, TrailMode, ServiceEndpoint } from './types';

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

function detectMode(did: string): TrailMode {
  const parts = did.split(':');
  if (parts.length < 4) return 'self';
  return (parts[2] as TrailMode) || 'self';
}
