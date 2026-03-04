import type { DidResolutionResult } from './types';
export declare class TrailResolver {
    private registryEndpoint?;
    constructor(options?: {
        registryEndpoint?: string;
    });
    resolve(did: string): Promise<DidResolutionResult>;
    resolveSelf(did: string): DidResolutionResult;
    private resolveRegistered;
}
/**
 * Extract public key bytes from a self-mode DID.
 * Useful for proof verification.
 */
export declare function extractPublicKeyFromSelfDid(did: string): Uint8Array;
