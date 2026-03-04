// TRAIL Protocol Core SDK
// https://trailprotocol.org
// License: Apache-2.0

export { generateKeyPair, publicKeyFromMultibase } from './keygen';
export { createSelfDid, createOrgDid, createAgentDid, parseTrailDid, normalizeSlug, computeTrailHash } from './did';
export { createDidDocument } from './document';
export { TrailResolver, extractPublicKeyFromSelfDid } from './resolver';
export { createProof, verifyProof } from './proof';
export { createSelfSignedCredential, verifyCredential } from './credential';
export { encodeMultibase, decodeMultibase } from './base58';
export { jcsCanonicalizeToString, jcsCanonicalizeToBuffer } from './jcs';

export type {
  TrailKeyPair,
  TrailMode,
  DidDocument,
  DidResolutionResult,
  VerificationMethod,
  ServiceEndpoint,
  DataIntegrityProof,
  VerifiableCredential,
  RecoveryPolicy,
} from './types';
