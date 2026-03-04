import { decodeMultibase } from './base58';
import { parseTrailDid } from './did';
import type { DidDocument, DidResolutionResult } from './types';

export class TrailResolver {
  private registryEndpoint?: string;

  constructor(options: { registryEndpoint?: string } = {}) {
    this.registryEndpoint = options.registryEndpoint;
  }

  async resolve(did: string): Promise<DidResolutionResult> {
    const parsed = parseTrailDid(did);

    if (parsed.mode === 'self') {
      return this.resolveSelf(did);
    }

    if (this.registryEndpoint) {
      return this.resolveRegistered(did);
    }

    throw new Error(
      `Cannot resolve ${parsed.mode}-mode DID without a registry. ` +
      `The TRAIL Registry is not yet available. ` +
      `Use self-signed mode (did:trail:self:) for local verification, ` +
      `or provide a registryEndpoint when constructing the resolver.`
    );
  }

  resolveSelf(did: string): DidResolutionResult {
    const parsed = parseTrailDid(did);

    if (parsed.mode !== 'self') {
      throw new Error(`resolveSelf only works with self-mode DIDs, got ${parsed.mode}`);
    }

    const publicKeyBytes = decodeMultibase(parsed.subject);

    if (publicKeyBytes.length !== 32) {
      throw new Error(
        `Invalid Ed25519 public key: expected 32 bytes, got ${publicKeyBytes.length}`
      );
    }

    const keyId = `${did}#key-1`;

    const didDocument: DidDocument = {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://trailprotocol.org/ns/did/v1',
      ],
      id: did,
      'trail:trailMode': 'self-signed',
      'trail:trailTrustTier': 0,
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

  private async resolveRegistered(did: string): Promise<DidResolutionResult> {
    const url = `${this.registryEndpoint}/identifiers/${did}`;
    const response = await fetch(url, {
      headers: { Accept: 'application/did+ld+json' },
    });

    if (!response.ok) {
      throw new Error(`Registry returned ${response.status}: ${await response.text()}`);
    }

    return response.json() as Promise<DidResolutionResult>;
  }
}

/**
 * Extract public key bytes from a self-mode DID.
 * Useful for proof verification.
 */
export function extractPublicKeyFromSelfDid(did: string): Uint8Array {
  const parsed = parseTrailDid(did);
  if (parsed.mode !== 'self') {
    throw new Error('Can only extract public key from self-mode DIDs');
  }
  return decodeMultibase(parsed.subject);
}
