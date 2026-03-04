import type { DidDocument, TrailKeyPair, TrailMode, ServiceEndpoint } from './types';
/**
 * Current TRAIL Protocol specification version.
 */
export declare const SPEC_VERSION = "1.1.0";
export interface CreateDocumentOptions {
    mode?: TrailMode;
    controller?: string;
    services?: ServiceEndpoint[];
    aiSystemType?: string;
    euAiActRiskClass?: string;
    parentOrganization?: string;
}
export declare function createDidDocument(did: string, keys: TrailKeyPair, options?: CreateDocumentOptions): DidDocument;
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
export declare function rotateKey(doc: DidDocument, newKeys: TrailKeyPair): {
    document: DidDocument;
    rotationMetadata: KeyRotationMetadata;
};
export interface KeyRotationMetadata {
    previousKeyId: string;
    newKeyId: string;
    rotatedAt: string;
    previousKeyRetained: boolean;
}
