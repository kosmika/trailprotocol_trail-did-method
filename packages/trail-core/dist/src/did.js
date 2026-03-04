"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeSlug = normalizeSlug;
exports.computeTrailHash = computeTrailHash;
exports.createSelfDid = createSelfDid;
exports.createOrgDid = createOrgDid;
exports.createAgentDid = createAgentDid;
exports.parseTrailDid = parseTrailDid;
const node_crypto_1 = require("node:crypto");
const LEGAL_SUFFIXES = [
    'gmbh', 'ag', 'inc', 'ltd', 'llc', 'corp', 'co', 'plc',
    'sa', 'srl', 'bv', 'nv', 'oy', 'ab', 'as', 'aps',
    'se', 'kg', 'ohg', 'ug', 'ev', 'eg', 'mbh', 'kgaa',
    'sarl', 'sas', 'spa', 'sl', 'pty', 'bhd', 'sdn',
    'corporation', 'company', 'limited', 'incorporated',
];
function normalizeSlug(input) {
    let slug = input.toLowerCase().trim();
    // Replace spaces, underscores, dots with hyphens
    slug = slug.replace(/[\s_\.]+/g, '-');
    // Remove all characters not in [a-z0-9-]
    slug = slug.replace(/[^a-z0-9-]/g, '');
    // Remove legal suffixes
    for (const suffix of LEGAL_SUFFIXES) {
        const pattern = new RegExp(`-${suffix}$`);
        slug = slug.replace(pattern, '');
    }
    // Collapse consecutive hyphens
    slug = slug.replace(/-+/g, '-');
    // Trim leading/trailing hyphens
    slug = slug.replace(/^-+|-+$/g, '');
    if (slug.length === 0) {
        throw new Error('Slug normalization resulted in empty string');
    }
    if (slug.length > 120) {
        throw new Error('Normalized slug exceeds 120 characters');
    }
    return slug;
}
function computeTrailHash(slug, publicKeyMultibase) {
    const input = `${slug}:${publicKeyMultibase}`;
    const hash = (0, node_crypto_1.createHash)('sha256').update(input).digest('hex');
    return hash.substring(0, 12);
}
function createSelfDid(publicKeyMultibase) {
    if (!publicKeyMultibase.startsWith('z')) {
        throw new Error('Public key multibase must start with z (base58btc)');
    }
    return `did:trail:self:${publicKeyMultibase}`;
}
function createOrgDid(subject, publicKeyMultibase) {
    const slug = normalizeSlug(subject);
    const hash = computeTrailHash(slug, publicKeyMultibase);
    return `did:trail:org:${slug}-${hash}`;
}
function createAgentDid(subject, publicKeyMultibase) {
    const slug = normalizeSlug(subject);
    const hash = computeTrailHash(slug, publicKeyMultibase);
    return `did:trail:agent:${slug}-${hash}`;
}
function parseTrailDid(did) {
    if (!did.startsWith('did:trail:')) {
        throw new Error(`Invalid TRAIL DID: must start with "did:trail:", got "${did}"`);
    }
    const rest = did.substring('did:trail:'.length);
    const colonIndex = rest.indexOf(':');
    if (colonIndex === -1) {
        throw new Error(`Invalid TRAIL DID: missing mode separator in "${did}"`);
    }
    const mode = rest.substring(0, colonIndex);
    const subject = rest.substring(colonIndex + 1);
    if (!['org', 'agent', 'self'].includes(mode)) {
        throw new Error(`Invalid TRAIL DID mode: "${mode}". Must be org, agent, or self.`);
    }
    if (subject.length === 0) {
        throw new Error('Invalid TRAIL DID: empty subject');
    }
    if (subject.length > 128) {
        throw new Error('Invalid TRAIL DID: subject exceeds 128 characters');
    }
    if (mode === 'self') {
        if (!subject.startsWith('z')) {
            throw new Error('Self-mode DID subject must be a multibase-encoded public key (z prefix)');
        }
        return { mode, subject };
    }
    // For org/agent, extract slug and hash
    const lastHyphen = subject.lastIndexOf('-');
    if (lastHyphen === -1 || subject.length - lastHyphen - 1 !== 12) {
        // Legacy format without hash — still parseable but flagged
        return { mode, subject, slug: subject };
    }
    const slug = subject.substring(0, lastHyphen);
    const hash = subject.substring(lastHyphen + 1);
    if (!/^[0-9a-f]{12}$/.test(hash)) {
        return { mode, subject, slug: subject };
    }
    return { mode, subject, slug, hash };
}
