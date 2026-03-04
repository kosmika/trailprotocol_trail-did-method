"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = require("node:test");
const assert = __importStar(require("node:assert/strict"));
const keygen_1 = require("../src/keygen");
const did_1 = require("../src/did");
const document_1 = require("../src/document");
const resolver_1 = require("../src/resolver");
const proof_1 = require("../src/proof");
const types_1 = require("../src/types");
const credential_1 = require("../src/credential");
const base58_1 = require("../src/base58");
const jcs_1 = require("../src/jcs");
(0, node_test_1.describe)('JCS (RFC 8785)', () => {
    (0, node_test_1.it)('sorts object keys by UTF-16 code unit order', () => {
        const input = { z: 1, a: 2, m: 3 };
        assert.strictEqual((0, jcs_1.jcsCanonicalizeToString)(input), '{"a":2,"m":3,"z":1}');
    });
    (0, node_test_1.it)('handles nested objects', () => {
        const input = { b: { d: 1, c: 2 }, a: 3 };
        assert.strictEqual((0, jcs_1.jcsCanonicalizeToString)(input), '{"a":3,"b":{"c":2,"d":1}}');
    });
    (0, node_test_1.it)('handles arrays (preserves order)', () => {
        const input = [3, 1, 2];
        assert.strictEqual((0, jcs_1.jcsCanonicalizeToString)(input), '[3,1,2]');
    });
    (0, node_test_1.it)('handles null and booleans', () => {
        assert.strictEqual((0, jcs_1.jcsCanonicalizeToString)(null), 'null');
        assert.strictEqual((0, jcs_1.jcsCanonicalizeToString)(true), 'true');
        assert.strictEqual((0, jcs_1.jcsCanonicalizeToString)(false), 'false');
    });
    (0, node_test_1.it)('handles -0 as 0', () => {
        assert.strictEqual((0, jcs_1.jcsCanonicalizeToString)(-0), '0');
    });
    (0, node_test_1.it)('escapes control characters in strings', () => {
        assert.strictEqual((0, jcs_1.jcsCanonicalizeToString)('a\nb'), '"a\\nb"');
        assert.strictEqual((0, jcs_1.jcsCanonicalizeToString)('a\tb'), '"a\\tb"');
    });
    (0, node_test_1.it)('skips undefined properties', () => {
        const input = { a: 1, b: undefined, c: 3 };
        assert.strictEqual((0, jcs_1.jcsCanonicalizeToString)(input), '{"a":1,"c":3}');
    });
    (0, node_test_1.it)('rejects NaN and Infinity', () => {
        assert.throws(() => (0, jcs_1.jcsCanonicalizeToString)(NaN), /NaN/);
        assert.throws(() => (0, jcs_1.jcsCanonicalizeToString)(Infinity), /Infinity/);
    });
    (0, node_test_1.it)('produces stable output for DID documents', () => {
        const doc = {
            '@context': ['https://www.w3.org/ns/did/v1'],
            id: 'did:trail:self:z6MkTest',
            verificationMethod: [{ id: '#key-1', type: 'JsonWebKey2020' }],
        };
        const result1 = (0, jcs_1.jcsCanonicalizeToString)(doc);
        const result2 = (0, jcs_1.jcsCanonicalizeToString)(doc);
        assert.strictEqual(result1, result2);
        // Keys should be sorted: @context < id < verificationMethod
        assert.ok(result1.indexOf('"@context"') < result1.indexOf('"id"'));
        assert.ok(result1.indexOf('"id"') < result1.indexOf('"verificationMethod"'));
    });
});
(0, node_test_1.describe)('Base58', () => {
    (0, node_test_1.it)('round-trips bytes', () => {
        const original = new Uint8Array([0, 0, 1, 2, 3, 255]);
        const encoded = (0, base58_1.encode)(original);
        const decoded = (0, base58_1.decode)(encoded);
        assert.deepStrictEqual(decoded, original);
    });
    (0, node_test_1.it)('handles empty input', () => {
        assert.strictEqual((0, base58_1.encode)(new Uint8Array(0)), '');
        assert.deepStrictEqual((0, base58_1.decode)(''), new Uint8Array(0));
    });
    (0, node_test_1.it)('multibase round-trips', () => {
        const bytes = new Uint8Array([1, 2, 3, 4, 5]);
        const mb = (0, base58_1.encodeMultibase)(bytes);
        assert.ok(mb.startsWith('z'));
        const decoded = (0, base58_1.decodeMultibase)(mb);
        assert.deepStrictEqual(decoded, bytes);
    });
    (0, node_test_1.it)('rejects non-z multibase prefix', () => {
        assert.throws(() => (0, base58_1.decodeMultibase)('m123'), /base58btc/);
    });
});
(0, node_test_1.describe)('Key Generation', () => {
    (0, node_test_1.it)('generates Ed25519 keypair', () => {
        const keys = (0, keygen_1.generateKeyPair)();
        assert.strictEqual(keys.publicKeyBytes.length, 32);
        assert.strictEqual(keys.privateKeyBytes.length, 32);
        assert.ok(keys.publicKeyMultibase.startsWith('z'));
        assert.strictEqual(keys.publicKeyJwk.kty, 'OKP');
        assert.strictEqual(keys.publicKeyJwk.crv, 'Ed25519');
    });
    (0, node_test_1.it)('generates unique keys each time', () => {
        const k1 = (0, keygen_1.generateKeyPair)();
        const k2 = (0, keygen_1.generateKeyPair)();
        assert.notDeepStrictEqual(k1.publicKeyBytes, k2.publicKeyBytes);
    });
});
(0, node_test_1.describe)('DID Construction', () => {
    (0, node_test_1.it)('creates self DID from multibase', () => {
        const keys = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createSelfDid)(keys.publicKeyMultibase);
        assert.ok(did.startsWith('did:trail:self:z'));
        assert.strictEqual(did, `did:trail:self:${keys.publicKeyMultibase}`);
    });
    (0, node_test_1.it)('creates org DID with hash suffix', () => {
        const keys = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createOrgDid)('ACME Corporation GmbH', keys.publicKeyMultibase);
        // normalizeSlug removes "GmbH" and "Corporation" as legal suffixes → "acme"
        assert.ok(did.startsWith('did:trail:org:acme-'));
        // Hash suffix is 12 hex chars
        const parts = did.split(':');
        const subject = parts[3];
        const hashPart = subject.split('-').pop();
        assert.strictEqual(hashPart.length, 12);
        assert.ok(/^[0-9a-f]{12}$/.test(hashPart));
    });
    (0, node_test_1.it)('creates agent DID with hash suffix', () => {
        const keys = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createAgentDid)('Sales Bot', keys.publicKeyMultibase);
        assert.ok(did.startsWith('did:trail:agent:sales-bot-'));
    });
    (0, node_test_1.it)('normalizes slugs consistently', () => {
        const keys = (0, keygen_1.generateKeyPair)();
        const d1 = (0, did_1.createOrgDid)('ACME Corp GmbH', keys.publicKeyMultibase);
        const d2 = (0, did_1.createOrgDid)('acme corp gmbh', keys.publicKeyMultibase);
        assert.strictEqual(d1, d2);
    });
    (0, node_test_1.it)('parses self DID', () => {
        const keys = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createSelfDid)(keys.publicKeyMultibase);
        const parsed = (0, did_1.parseTrailDid)(did);
        assert.strictEqual(parsed.mode, 'self');
        assert.strictEqual(parsed.subject, keys.publicKeyMultibase);
    });
    (0, node_test_1.it)('parses org DID', () => {
        const keys = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createOrgDid)('Test Org', keys.publicKeyMultibase);
        const parsed = (0, did_1.parseTrailDid)(did);
        assert.strictEqual(parsed.mode, 'org');
        assert.ok(parsed.slug);
        assert.ok(parsed.hash);
        assert.strictEqual(parsed.hash.length, 12);
    });
    (0, node_test_1.it)('rejects invalid DID format', () => {
        assert.throws(() => (0, did_1.parseTrailDid)('did:web:example.com'), /must start with/i);
        assert.throws(() => (0, did_1.parseTrailDid)('did:trail:unknown:abc'), /invalid trail did mode/i);
    });
});
(0, node_test_1.describe)('DID Document', () => {
    (0, node_test_1.it)('creates self DID document', () => {
        const keys = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createSelfDid)(keys.publicKeyMultibase);
        const doc = (0, document_1.createDidDocument)(did, keys, { mode: 'self' });
        assert.strictEqual(doc.id, did);
        assert.ok(doc['@context'].includes('https://www.w3.org/ns/did/v1'));
        assert.strictEqual(doc.verificationMethod.length, 1);
        assert.strictEqual(doc.verificationMethod[0].type, 'JsonWebKey2020');
        assert.deepStrictEqual(doc.verificationMethod[0].publicKeyJwk, keys.publicKeyJwk);
        assert.strictEqual(doc['trail:trailMode'], 'self'); // mode string, not 'self-signed'
        assert.strictEqual(doc['trail:trailTrustTier'], 0); // Tier 0 for self mode
    });
    (0, node_test_1.it)('creates org DID document with service endpoint', () => {
        const keys = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createOrgDid)('Test Corp', keys.publicKeyMultibase);
        const doc = (0, document_1.createDidDocument)(did, keys, { mode: 'org' });
        assert.strictEqual(doc['trail:trailMode'], 'org');
        assert.ok(doc.service && doc.service.length > 0);
    });
    (0, node_test_1.it)('creates agent DID document with parent reference', () => {
        const keys = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createAgentDid)('Bot', keys.publicKeyMultibase);
        const parentDid = 'did:trail:org:parent-corp-abcd1234e5f6';
        const doc = (0, document_1.createDidDocument)(did, keys, {
            mode: 'agent',
            parentOrganization: parentDid,
            aiSystemType: 'agent',
        });
        assert.strictEqual(doc['trail:trailMode'], 'agent');
        assert.strictEqual(doc['trail:parentOrganization'], parentDid);
        assert.strictEqual(doc['trail:aiSystemType'], 'agent');
    });
});
(0, node_test_1.describe)('Self-Mode Resolution', () => {
    (0, node_test_1.it)('resolves self DID offline', async () => {
        const keys = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createSelfDid)(keys.publicKeyMultibase);
        const resolver = new resolver_1.TrailResolver();
        const result = await resolver.resolve(did);
        assert.strictEqual(result.didDocument.id, did);
        assert.strictEqual(result.didResolutionMetadata['contentType'], 'application/did+ld+json');
        assert.strictEqual(result.didDocument.verificationMethod[0].publicKeyJwk.crv, 'Ed25519');
        assert.strictEqual(result.didDocument['trail:trailTrustTier'], 0);
    });
    (0, node_test_1.it)('rejects invalid self DID multibase', async () => {
        const resolver = new resolver_1.TrailResolver();
        await assert.rejects(() => resolver.resolve('did:trail:self:invalidmultibase'), /multibase/i);
    });
});
(0, node_test_1.describe)('DataIntegrityProof', () => {
    (0, node_test_1.it)('creates and verifies proof', () => {
        const keys = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createSelfDid)(keys.publicKeyMultibase);
        const doc = { id: did, name: 'Test Document' };
        const proof = (0, proof_1.createProof)(doc, keys.privateKeyBytes, `${did}#key-0`, 'assertionMethod');
        assert.strictEqual(proof.type, 'DataIntegrityProof');
        assert.strictEqual(proof.cryptosuite, 'eddsa-jcs-2023');
        assert.strictEqual(proof.verificationMethod, `${did}#key-0`);
        assert.ok(proof.proofValue.startsWith('z'));
        const valid = (0, proof_1.verifyProof)(doc, proof, keys.publicKeyBytes);
        assert.ok(valid);
    });
    (0, node_test_1.it)('rejects tampered document', () => {
        const keys = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createSelfDid)(keys.publicKeyMultibase);
        const doc = { id: did, name: 'Original' };
        const proof = (0, proof_1.createProof)(doc, keys.privateKeyBytes, `${did}#key-0`, 'assertionMethod');
        const tampered = { id: did, name: 'Tampered' };
        const valid = (0, proof_1.verifyProof)(tampered, proof, keys.publicKeyBytes);
        assert.ok(!valid);
    });
    (0, node_test_1.it)('rejects wrong key', () => {
        const keys1 = (0, keygen_1.generateKeyPair)();
        const keys2 = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createSelfDid)(keys1.publicKeyMultibase);
        const doc = { id: did, data: 'test' };
        const proof = (0, proof_1.createProof)(doc, keys1.privateKeyBytes, `${did}#key-0`, 'assertionMethod');
        const valid = (0, proof_1.verifyProof)(doc, proof, keys2.publicKeyBytes);
        assert.ok(!valid);
    });
});
(0, node_test_1.describe)('Verifiable Credentials', () => {
    (0, node_test_1.it)('creates and verifies self-signed credential', () => {
        const keys = (0, keygen_1.generateKeyPair)();
        const issuerDid = (0, did_1.createSelfDid)(keys.publicKeyMultibase);
        const subjectDid = (0, did_1.createSelfDid)((0, keygen_1.generateKeyPair)().publicKeyMultibase);
        const vc = (0, credential_1.createSelfSignedCredential)(issuerDid, subjectDid, { name: 'Test Agent', role: 'assistant' }, keys.privateKeyBytes);
        assert.ok(vc['@context'].includes('https://www.w3.org/2018/credentials/v1'));
        assert.ok(vc.type.includes('VerifiableCredential'));
        assert.strictEqual(vc.issuer, issuerDid);
        assert.strictEqual(vc.credentialSubject['id'], subjectDid);
        assert.strictEqual(vc.credentialSubject['name'], 'Test Agent');
        assert.ok(vc.proof);
        const result = (0, credential_1.verifyCredential)(vc, keys.publicKeyBytes);
        assert.ok(result.valid, `Verification failed: ${result.errors.join(', ')}`);
        assert.strictEqual(result.errors.length, 0);
    });
    (0, node_test_1.it)('detects missing proof', () => {
        const keys = (0, keygen_1.generateKeyPair)();
        const vc = {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiableCredential'],
            issuer: 'did:trail:self:z6Mk...',
            issuanceDate: new Date().toISOString(),
            credentialSubject: { id: 'did:trail:self:z6Mk...' },
        };
        const result = (0, credential_1.verifyCredential)(vc, keys.publicKeyBytes);
        assert.ok(!result.valid);
        assert.ok(result.errors.some(e => /proof/i.test(e)));
    });
    (0, node_test_1.it)('detects tampered claims', () => {
        const keys = (0, keygen_1.generateKeyPair)();
        const issuerDid = (0, did_1.createSelfDid)(keys.publicKeyMultibase);
        const subjectDid = (0, did_1.createSelfDid)((0, keygen_1.generateKeyPair)().publicKeyMultibase);
        const vc = (0, credential_1.createSelfSignedCredential)(issuerDid, subjectDid, { role: 'assistant' }, keys.privateKeyBytes);
        // Tamper with credential
        vc.credentialSubject['role'] = 'admin';
        const result = (0, credential_1.verifyCredential)(vc, keys.publicKeyBytes);
        assert.ok(!result.valid);
    });
});
(0, node_test_1.describe)('End-to-End Roundtrip', () => {
    (0, node_test_1.it)('keygen → DID → resolve → sign → verify', async () => {
        // Step 1: Generate keys
        const orgKeys = (0, keygen_1.generateKeyPair)();
        const agentKeys = (0, keygen_1.generateKeyPair)();
        // Step 2: Create DIDs
        const orgDid = (0, did_1.createOrgDid)('ACME Corporation', orgKeys.publicKeyMultibase);
        const agentDid = (0, did_1.createAgentDid)('Sales Assistant', agentKeys.publicKeyMultibase);
        const selfDid = (0, did_1.createSelfDid)(orgKeys.publicKeyMultibase);
        // Step 3: Create DID Documents
        const orgDoc = (0, document_1.createDidDocument)(orgDid, orgKeys, { mode: 'org' });
        const agentDoc = (0, document_1.createDidDocument)(agentDid, agentKeys, {
            mode: 'agent',
            parentOrganization: orgDid,
            aiSystemType: 'agent',
        });
        assert.strictEqual(orgDoc.id, orgDid);
        assert.strictEqual(agentDoc['trail:parentOrganization'], orgDid);
        // Step 4: Resolve self DID (offline)
        const resolver = new resolver_1.TrailResolver();
        const resolved = await resolver.resolve(selfDid);
        assert.strictEqual(resolved.didDocument.id, selfDid);
        // Step 5: Create a Verifiable Credential
        const vc = (0, credential_1.createSelfSignedCredential)(selfDid, agentDid, {
            name: 'Sales Assistant',
            parentOrganization: orgDid,
            aiSystemType: 'conversational-agent',
        }, orgKeys.privateKeyBytes);
        // Step 6: Verify the credential
        const verification = (0, credential_1.verifyCredential)(vc, orgKeys.publicKeyBytes);
        assert.ok(verification.valid, `VC verification failed: ${verification.errors.join(', ')}`);
        // Step 7: Verify proof directly
        const proof = vc.proof;
        const vcWithoutProof = { ...vc };
        delete vcWithoutProof.proof;
        const proofValid = (0, proof_1.verifyProof)(vcWithoutProof, proof, orgKeys.publicKeyBytes);
        assert.ok(proofValid);
        console.log('✓ Full roundtrip: keygen → DID → resolve → VC sign → VC verify');
    });
});
(0, node_test_1.describe)('Crypto Agility', () => {
    (0, node_test_1.it)('DEFAULT_CRYPTOSUITE is eddsa-jcs-2023', () => {
        assert.strictEqual(proof_1.DEFAULT_CRYPTOSUITE, 'eddsa-jcs-2023');
    });
    (0, node_test_1.it)('isSupportedCryptosuite validates known suites', () => {
        assert.ok((0, proof_1.isSupportedCryptosuite)('eddsa-jcs-2023'));
        assert.ok(!(0, proof_1.isSupportedCryptosuite)('ecdsa-rdfc-2019'));
        assert.ok(!(0, proof_1.isSupportedCryptosuite)('unknown-suite'));
        assert.ok(!(0, proof_1.isSupportedCryptosuite)(''));
    });
    (0, node_test_1.it)('SUPPORTED_CRYPTOSUITES registry has required fields', () => {
        assert.ok(types_1.SUPPORTED_CRYPTOSUITES.length >= 1);
        for (const suite of types_1.SUPPORTED_CRYPTOSUITES) {
            assert.ok(suite.id);
            assert.ok(suite.algorithm);
            assert.ok(suite.canonicalization);
            assert.ok(suite.keyType);
            assert.ok(['active', 'deprecated'].includes(suite.status));
        }
    });
    (0, node_test_1.it)('createProof accepts explicit cryptosuite parameter', () => {
        const keys = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createSelfDid)(keys.publicKeyMultibase);
        const doc = { id: did, data: 'test' };
        const proof = (0, proof_1.createProof)(doc, keys.privateKeyBytes, `${did}#key-1`, 'assertionMethod', 'eddsa-jcs-2023');
        assert.strictEqual(proof.cryptosuite, 'eddsa-jcs-2023');
        const valid = (0, proof_1.verifyProof)(doc, proof, keys.publicKeyBytes);
        assert.ok(valid);
    });
    (0, node_test_1.it)('createProof rejects unsupported cryptosuite', () => {
        const keys = (0, keygen_1.generateKeyPair)();
        const doc = { id: 'test' };
        assert.throws(() => (0, proof_1.createProof)(doc, keys.privateKeyBytes, 'test#key-1', 'assertionMethod', 'unknown-suite'), /Unsupported cryptosuite/);
    });
    (0, node_test_1.it)('DID document includes supportedCryptosuites', () => {
        const keys = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createSelfDid)(keys.publicKeyMultibase);
        const doc = (0, document_1.createDidDocument)(did, keys, { mode: 'self' });
        assert.ok(doc['trail:supportedCryptosuites']);
        assert.ok(Array.isArray(doc['trail:supportedCryptosuites']));
        assert.ok(doc['trail:supportedCryptosuites'].includes('eddsa-jcs-2023'));
    });
});
(0, node_test_1.describe)('Spec Version', () => {
    (0, node_test_1.it)('SPEC_VERSION is 1.1.0', () => {
        assert.strictEqual(document_1.SPEC_VERSION, '1.1.0');
    });
    (0, node_test_1.it)('DID document includes trail:specVersion', () => {
        const keys = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createSelfDid)(keys.publicKeyMultibase);
        const doc = (0, document_1.createDidDocument)(did, keys, { mode: 'self' });
        assert.strictEqual(doc['trail:specVersion'], '1.1.0');
    });
    (0, node_test_1.it)('resolved self DID includes trail:specVersion', async () => {
        const keys = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createSelfDid)(keys.publicKeyMultibase);
        const resolver = new resolver_1.TrailResolver();
        const result = await resolver.resolve(did);
        assert.strictEqual(result.didDocument['trail:specVersion'], '1.1.0');
    });
    (0, node_test_1.it)('resolved self DID includes supportedCryptosuites', async () => {
        const keys = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createSelfDid)(keys.publicKeyMultibase);
        const resolver = new resolver_1.TrailResolver();
        const result = await resolver.resolve(did);
        assert.ok(result.didDocument['trail:supportedCryptosuites']);
        assert.ok(result.didDocument['trail:supportedCryptosuites'].includes('eddsa-jcs-2023'));
    });
});
(0, node_test_1.describe)('Key Rotation', () => {
    (0, node_test_1.it)('rotates key for org DID', () => {
        const keys1 = (0, keygen_1.generateKeyPair)();
        const keys2 = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createOrgDid)('Test Corp', keys1.publicKeyMultibase);
        const doc = (0, document_1.createDidDocument)(did, keys1, { mode: 'org' });
        const { document: rotated, rotationMetadata } = (0, document_1.rotateKey)(doc, keys2);
        // New key is added
        assert.strictEqual(rotated.verificationMethod.length, 2);
        assert.strictEqual(rotated.verificationMethod[1].id, `${did}#key-2`);
        assert.deepStrictEqual(rotated.verificationMethod[1].publicKeyJwk, keys2.publicKeyJwk);
        // Old key is retained
        assert.strictEqual(rotated.verificationMethod[0].id, `${did}#key-1`);
        assert.deepStrictEqual(rotated.verificationMethod[0].publicKeyJwk, keys1.publicKeyJwk);
        // Active key references updated
        assert.deepStrictEqual(rotated.authentication, [`${did}#key-2`]);
        assert.deepStrictEqual(rotated.assertionMethod, [`${did}#key-2`]);
        // Metadata
        assert.strictEqual(rotationMetadata.previousKeyId, `${did}#key-1`);
        assert.strictEqual(rotationMetadata.newKeyId, `${did}#key-2`);
        assert.ok(rotationMetadata.rotatedAt);
        assert.ok(rotationMetadata.previousKeyRetained);
    });
    (0, node_test_1.it)('rotates key for agent DID', () => {
        const keys1 = (0, keygen_1.generateKeyPair)();
        const keys2 = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createAgentDid)('Sales Bot', keys1.publicKeyMultibase);
        const doc = (0, document_1.createDidDocument)(did, keys1, { mode: 'agent' });
        const { document: rotated } = (0, document_1.rotateKey)(doc, keys2);
        assert.strictEqual(rotated.verificationMethod.length, 2);
        assert.deepStrictEqual(rotated.authentication, [`${did}#key-2`]);
    });
    (0, node_test_1.it)('rejects key rotation for self DID', () => {
        const keys1 = (0, keygen_1.generateKeyPair)();
        const keys2 = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createSelfDid)(keys1.publicKeyMultibase);
        const doc = (0, document_1.createDidDocument)(did, keys1, { mode: 'self' });
        assert.throws(() => (0, document_1.rotateKey)(doc, keys2), /not supported for self-mode/);
    });
    (0, node_test_1.it)('supports multiple rotations', () => {
        const keys1 = (0, keygen_1.generateKeyPair)();
        const keys2 = (0, keygen_1.generateKeyPair)();
        const keys3 = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createOrgDid)('Multi Rotate Corp', keys1.publicKeyMultibase);
        const doc = (0, document_1.createDidDocument)(did, keys1, { mode: 'org' });
        const { document: rotated1 } = (0, document_1.rotateKey)(doc, keys2);
        const { document: rotated2, rotationMetadata } = (0, document_1.rotateKey)(rotated1, keys3);
        assert.strictEqual(rotated2.verificationMethod.length, 3);
        assert.deepStrictEqual(rotated2.authentication, [`${did}#key-3`]);
        assert.strictEqual(rotationMetadata.previousKeyId, `${did}#key-2`);
        assert.strictEqual(rotationMetadata.newKeyId, `${did}#key-3`);
    });
    (0, node_test_1.it)('proofs signed with new key verify after rotation', () => {
        const keys1 = (0, keygen_1.generateKeyPair)();
        const keys2 = (0, keygen_1.generateKeyPair)();
        const did = (0, did_1.createOrgDid)('Proof Rotate', keys1.publicKeyMultibase);
        const doc = (0, document_1.createDidDocument)(did, keys1, { mode: 'org' });
        const { document: rotated } = (0, document_1.rotateKey)(doc, keys2);
        const testDoc = { id: did, data: 'after rotation' };
        // Sign with new key
        const proof = (0, proof_1.createProof)(testDoc, keys2.privateKeyBytes, `${did}#key-2`);
        assert.ok((0, proof_1.verifyProof)(testDoc, proof, keys2.publicKeyBytes));
        // Old key proofs still verify against old key
        const oldProof = (0, proof_1.createProof)(testDoc, keys1.privateKeyBytes, `${did}#key-1`);
        assert.ok((0, proof_1.verifyProof)(testDoc, oldProof, keys1.publicKeyBytes));
    });
});
