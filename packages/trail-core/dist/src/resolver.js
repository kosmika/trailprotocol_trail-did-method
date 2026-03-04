"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TrailResolver = void 0;
exports.extractPublicKeyFromSelfDid = extractPublicKeyFromSelfDid;
const base58_1 = require("./base58");
const did_1 = require("./did");
const types_1 = require("./types");
const document_1 = require("./document");
class TrailResolver {
    registryEndpoint;
    constructor(options = {}) {
        this.registryEndpoint = options.registryEndpoint;
    }
    async resolve(did) {
        const parsed = (0, did_1.parseTrailDid)(did);
        if (parsed.mode === 'self') {
            return this.resolveSelf(did);
        }
        if (this.registryEndpoint) {
            return this.resolveRegistered(did);
        }
        throw new Error(`Cannot resolve ${parsed.mode}-mode DID without a registry. ` +
            `The TRAIL Registry is not yet available. ` +
            `Use self-signed mode (did:trail:self:) for local verification, ` +
            `or provide a registryEndpoint when constructing the resolver.`);
    }
    resolveSelf(did) {
        const parsed = (0, did_1.parseTrailDid)(did);
        if (parsed.mode !== 'self') {
            throw new Error(`resolveSelf only works with self-mode DIDs, got ${parsed.mode}`);
        }
        const publicKeyBytes = (0, base58_1.decodeMultibase)(parsed.subject);
        if (publicKeyBytes.length !== 32) {
            throw new Error(`Invalid Ed25519 public key: expected 32 bytes, got ${publicKeyBytes.length}`);
        }
        const keyId = `${did}#key-1`;
        const didDocument = {
            '@context': [
                'https://www.w3.org/ns/did/v1',
                'https://trailprotocol.org/ns/did/v1',
            ],
            id: did,
            'trail:trailMode': 'self-signed',
            'trail:trailTrustTier': 0,
            'trail:specVersion': document_1.SPEC_VERSION,
            'trail:supportedCryptosuites': types_1.SUPPORTED_CRYPTOSUITES
                .filter(s => s.status === 'active')
                .map(s => s.id),
            verificationMethod: [
                {
                    id: keyId,
                    type: 'JsonWebKey2020',
                    controller: did,
                    publicKeyJwk: {
                        kty: 'OKP',
                        crv: 'Ed25519',
                        x: Buffer.from(publicKeyBytes).toString('base64url'),
                    },
                },
            ],
            authentication: [keyId],
            assertionMethod: [keyId],
        };
        return {
            didDocument,
            didDocumentMetadata: {
                created: new Date().toISOString(),
                deactivated: false,
                trailTrustTier: 0,
            },
            didResolutionMetadata: {
                contentType: 'application/did+ld+json',
                resolvedLocally: true,
            },
        };
    }
    async resolveRegistered(did) {
        const url = `${this.registryEndpoint}/identifiers/${did}`;
        const response = await fetch(url, {
            headers: { Accept: 'application/did+ld+json' },
        });
        if (!response.ok) {
            throw new Error(`Registry returned ${response.status}: ${await response.text()}`);
        }
        return response.json();
    }
}
exports.TrailResolver = TrailResolver;
/**
 * Extract public key bytes from a self-mode DID.
 * Useful for proof verification.
 */
function extractPublicKeyFromSelfDid(did) {
    const parsed = (0, did_1.parseTrailDid)(did);
    if (parsed.mode !== 'self') {
        throw new Error('Can only extract public key from self-mode DIDs');
    }
    return (0, base58_1.decodeMultibase)(parsed.subject);
}
