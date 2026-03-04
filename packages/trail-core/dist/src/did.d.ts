import type { TrailMode } from './types';
export declare function normalizeSlug(input: string): string;
export declare function computeTrailHash(slug: string, publicKeyMultibase: string): string;
export declare function createSelfDid(publicKeyMultibase: string): string;
export declare function createOrgDid(subject: string, publicKeyMultibase: string): string;
export declare function createAgentDid(subject: string, publicKeyMultibase: string): string;
export interface ParsedDid {
    mode: TrailMode;
    subject: string;
    slug?: string;
    hash?: string;
}
export declare function parseTrailDid(did: string): ParsedDid;
