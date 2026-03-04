"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_CRYPTOSUITE = void 0;
exports.isSupportedCryptosuite = isSupportedCryptosuite;
exports.createProof = createProof;
exports.verifyProof = verifyProof;
const node_crypto_1 = require("node:crypto");
const base58_1 = require("./base58");
const keygen_1 = require("./keygen");
const jcs_1 = require("./jcs");
const types_1 = require("./types");
/**
 * Default cryptosuite used when none is specified.
 */
exports.DEFAULT_CRYPTOSUITE = 'eddsa-jcs-2023';
/**
 * Check whether a cryptosuite identifier is supported by this implementation.
 */
function isSupportedCryptosuite(id) {
    return types_1.SUPPORTED_CRYPTOSUITES.some(s => s.id === id && s.status === 'active');
}
/**
 * Create a DataIntegrityProof for a document using Ed25519.
 *
 * @param document - The document to sign
 * @param privateKeyBytes - Ed25519 private key (32 bytes)
 * @param verificationMethod - DID URL of the verification method (e.g. did:trail:self:z6Mk...#key-1)
 * @param proofPurpose - Proof purpose (default: assertionMethod)
 * @param cryptosuite - Cryptosuite to use (default: eddsa-jcs-2023). Enables crypto agility.
 */
function createProof(document, privateKeyBytes, verificationMethod, proofPurpose = 'assertionMethod', cryptosuite = exports.DEFAULT_CRYPTOSUITE) {
    if (!isSupportedCryptosuite(cryptosuite)) {
        throw new Error(`Unsupported cryptosuite: "${cryptosuite}". ` +
            `Supported: ${types_1.SUPPORTED_CRYPTOSUITES.filter(s => s.status === 'active').map(s => s.id).join(', ')}`);
    }
    const canonical = (0, jcs_1.jcsCanonicalizeToBuffer)(document);
    const privateKey = (0, keygen_1.createPrivateKeyObject)(privateKeyBytes);
    const signature = (0, node_crypto_1.sign)(null, canonical, privateKey);
    const proofValue = (0, base58_1.encodeMultibase)(new Uint8Array(signature));
    return {
        type: 'DataIntegrityProof',
        cryptosuite,
        created: new Date().toISOString(),
        verificationMethod,
        proofPurpose,
        proofValue,
    };
}
/**
 * Verify a DataIntegrityProof against a document using Ed25519.
 *
 * Supports crypto agility: verifies any proof whose cryptosuite is in the
 * SUPPORTED_CRYPTOSUITES registry and has status 'active'.
 */
function verifyProof(document, proof, publicKeyBytes) {
    if (proof.type !== 'DataIntegrityProof')
        return false;
    if (!isSupportedCryptosuite(proof.cryptosuite))
        return false;
    try {
        // Remove proof from document for verification
        const docWithoutProof = { ...document };
        delete docWithoutProof['proof'];
        const canonical = (0, jcs_1.jcsCanonicalizeToBuffer)(docWithoutProof);
        const signature = (0, base58_1.decodeMultibase)(proof.proofValue);
        const publicKey = (0, keygen_1.createPublicKeyObject)(publicKeyBytes);
        return (0, node_crypto_1.verify)(null, canonical, publicKey, Buffer.from(signature));
    }
    catch {
        return false;
    }
}
