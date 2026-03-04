import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { generateKeyPair } from '../src/keygen';
import { createSelfDid, createOrgDid, createAgentDid, parseTrailDid } from '../src/did';
import { createDidDocument } from '../src/document';
import { TrailResolver } from '../src/resolver';
import { createProof, verifyProof } from '../src/proof';
import { createSelfSignedCredential, verifyCredential } from '../src/credential';
import { encode, decode, encodeMultibase, decodeMultibase } from '../src/base58';

describe('Base58', () => {
  it('round-trips bytes', () => {
    const original = new Uint8Array([0, 0, 1, 2, 3, 255]);
    const encoded = encode(original);
    const decoded = decode(encoded);
    assert.deepStrictEqual(decoded, original);
  });

  it('handles empty input', () => {
    assert.strictEqual(encode(new Uint8Array(0)), '');
    assert.deepStrictEqual(decode(''), new Uint8Array(0));
  });

  it('multibase round-trips', () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    const mb = encodeMultibase(bytes);
    assert.ok(mb.startsWith('z'));
    const decoded = decodeMultibase(mb);
    assert.deepStrictEqual(decoded, bytes);
  });

  it('rejects non-z multibase prefix', () => {
    assert.throws(() => decodeMultibase('m123'), /base58btc/);
  });
});

describe('Key Generation', () => {
  it('generates Ed25519 keypair', () => {
    const keys = generateKeyPair();
    assert.strictEqual(keys.publicKeyBytes.length, 32);
    assert.strictEqual(keys.privateKeyBytes.length, 32);
    assert.ok(keys.publicKeyMultibase.startsWith('z'));
    assert.strictEqual(keys.publicKeyJwk.kty, 'OKP');
    assert.strictEqual(keys.publicKeyJwk.crv, 'Ed25519');
  });

  it('generates unique keys each time', () => {
    const k1 = generateKeyPair();
    const k2 = generateKeyPair();
    assert.notDeepStrictEqual(k1.publicKeyBytes, k2.publicKeyBytes);
  });
});

describe('DID Construction', () => {
  it('creates self DID from multibase', () => {
    const keys = generateKeyPair();
    const did = createSelfDid(keys.publicKeyMultibase);
    assert.ok(did.startsWith('did:trail:self:z'));
    assert.strictEqual(did, `did:trail:self:${keys.publicKeyMultibase}`);
  });

  it('creates org DID with hash suffix', () => {
    const keys = generateKeyPair();
    const did = createOrgDid('ACME Corporation GmbH', keys.publicKeyMultibase);
    // normalizeSlug removes "GmbH" and "Corporation" as legal suffixes → "acme"
    assert.ok(did.startsWith('did:trail:org:acme-'));
    // Hash suffix is 8 hex chars
    const parts = did.split(':');
    const subject = parts[3];
    const hashPart = subject.split('-').pop()!;
    assert.strictEqual(hashPart.length, 8);
    assert.ok(/^[0-9a-f]{8}$/.test(hashPart));
  });

  it('creates agent DID with hash suffix', () => {
    const keys = generateKeyPair();
    const did = createAgentDid('Sales Bot', keys.publicKeyMultibase);
    assert.ok(did.startsWith('did:trail:agent:sales-bot-'));
  });

  it('normalizes slugs consistently', () => {
    const keys = generateKeyPair();
    const d1 = createOrgDid('ACME Corp GmbH', keys.publicKeyMultibase);
    const d2 = createOrgDid('acme corp gmbh', keys.publicKeyMultibase);
    assert.strictEqual(d1, d2);
  });

  it('parses self DID', () => {
    const keys = generateKeyPair();
    const did = createSelfDid(keys.publicKeyMultibase);
    const parsed = parseTrailDid(did);
    assert.strictEqual(parsed.mode, 'self');
    assert.strictEqual(parsed.subject, keys.publicKeyMultibase);
  });

  it('parses org DID', () => {
    const keys = generateKeyPair();
    const did = createOrgDid('Test Org', keys.publicKeyMultibase);
    const parsed = parseTrailDid(did);
    assert.strictEqual(parsed.mode, 'org');
    assert.ok(parsed.slug);
    assert.ok(parsed.hash);
    assert.strictEqual(parsed.hash!.length, 8);
  });

  it('rejects invalid DID format', () => {
    assert.throws(() => parseTrailDid('did:web:example.com'), /must start with/i);
    assert.throws(() => parseTrailDid('did:trail:unknown:abc'), /invalid trail did mode/i);
  });
});

describe('DID Document', () => {
  it('creates self DID document', () => {
    const keys = generateKeyPair();
    const did = createSelfDid(keys.publicKeyMultibase);
    const doc = createDidDocument(did, keys, { mode: 'self' });

    assert.strictEqual(doc.id, did);
    assert.ok(doc['@context'].includes('https://www.w3.org/ns/did/v1'));
    assert.strictEqual(doc.verificationMethod.length, 1);
    assert.strictEqual(doc.verificationMethod[0].type, 'JsonWebKey2020');
    assert.deepStrictEqual(doc.verificationMethod[0].publicKeyJwk, keys.publicKeyJwk);
    assert.strictEqual(doc['trail:trailMode'], 'self');  // mode string, not 'self-signed'
    assert.strictEqual(doc['trail:trailTrustTier'], 0);  // Tier 0 for self mode
  });

  it('creates org DID document with service endpoint', () => {
    const keys = generateKeyPair();
    const did = createOrgDid('Test Corp', keys.publicKeyMultibase);
    const doc = createDidDocument(did, keys, { mode: 'org' });

    assert.strictEqual(doc['trail:trailMode'], 'org');
    assert.ok(doc.service && doc.service.length > 0);
  });

  it('creates agent DID document with parent reference', () => {
    const keys = generateKeyPair();
    const did = createAgentDid('Bot', keys.publicKeyMultibase);
    const parentDid = 'did:trail:org:parent-corp-abcd1234';
    const doc = createDidDocument(did, keys, {
      mode: 'agent',
      parentOrganization: parentDid,
      aiSystemType: 'agent',
    });

    assert.strictEqual(doc['trail:trailMode'], 'agent');
    assert.strictEqual(doc['trail:parentOrganization'], parentDid);
    assert.strictEqual(doc['trail:aiSystemType'], 'agent');
  });
});

describe('Self-Mode Resolution', () => {
  it('resolves self DID offline', async () => {
    const keys = generateKeyPair();
    const did = createSelfDid(keys.publicKeyMultibase);

    const resolver = new TrailResolver();
    const result = await resolver.resolve(did);

    assert.strictEqual(result.didDocument.id, did);
    assert.strictEqual(result.didResolutionMetadata['contentType'], 'application/did+ld+json');
    assert.strictEqual(result.didDocument.verificationMethod[0].publicKeyJwk.crv, 'Ed25519');
    assert.strictEqual(result.didDocument['trail:trailTrustTier'], 0);
  });

  it('rejects invalid self DID multibase', async () => {
    const resolver = new TrailResolver();
    await assert.rejects(
      () => resolver.resolve('did:trail:self:invalidmultibase'),
      /multibase/i
    );
  });
});

describe('DataIntegrityProof', () => {
  it('creates and verifies proof', () => {
    const keys = generateKeyPair();
    const did = createSelfDid(keys.publicKeyMultibase);
    const doc = { id: did, name: 'Test Document' };

    const proof = createProof(
      doc,
      keys.privateKeyBytes,
      `${did}#key-0`,
      'assertionMethod'
    );

    assert.strictEqual(proof.type, 'DataIntegrityProof');
    assert.strictEqual(proof.cryptosuite, 'eddsa-2022');
    assert.strictEqual(proof.verificationMethod, `${did}#key-0`);
    assert.ok(proof.proofValue.startsWith('z'));

    const valid = verifyProof(doc, proof, keys.publicKeyBytes);
    assert.ok(valid);
  });

  it('rejects tampered document', () => {
    const keys = generateKeyPair();
    const did = createSelfDid(keys.publicKeyMultibase);
    const doc = { id: did, name: 'Original' };

    const proof = createProof(
      doc,
      keys.privateKeyBytes,
      `${did}#key-0`,
      'assertionMethod'
    );

    const tampered = { id: did, name: 'Tampered' };
    const valid = verifyProof(tampered, proof, keys.publicKeyBytes);
    assert.ok(!valid);
  });

  it('rejects wrong key', () => {
    const keys1 = generateKeyPair();
    const keys2 = generateKeyPair();
    const did = createSelfDid(keys1.publicKeyMultibase);
    const doc = { id: did, data: 'test' };

    const proof = createProof(
      doc,
      keys1.privateKeyBytes,
      `${did}#key-0`,
      'assertionMethod'
    );

    const valid = verifyProof(doc, proof, keys2.publicKeyBytes);
    assert.ok(!valid);
  });
});

describe('Verifiable Credentials', () => {
  it('creates and verifies self-signed credential', () => {
    const keys = generateKeyPair();
    const issuerDid = createSelfDid(keys.publicKeyMultibase);
    const subjectDid = createSelfDid(generateKeyPair().publicKeyMultibase);

    const vc = createSelfSignedCredential(
      issuerDid,
      subjectDid,
      { name: 'Test Agent', role: 'assistant' },
      keys.privateKeyBytes
    );

    assert.ok(vc['@context'].includes('https://www.w3.org/2018/credentials/v1'));
    assert.ok(vc.type.includes('VerifiableCredential'));
    assert.strictEqual(vc.issuer, issuerDid);
    assert.strictEqual(vc.credentialSubject['id'], subjectDid);
    assert.strictEqual(vc.credentialSubject['name'], 'Test Agent');
    assert.ok(vc.proof);

    const result = verifyCredential(vc, keys.publicKeyBytes);
    assert.ok(result.valid, `Verification failed: ${result.errors.join(', ')}`);
    assert.strictEqual(result.errors.length, 0);
  });

  it('detects missing proof', () => {
    const keys = generateKeyPair();
    const vc = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential'],
      issuer: 'did:trail:self:z6Mk...',
      issuanceDate: new Date().toISOString(),
      credentialSubject: { id: 'did:trail:self:z6Mk...' },
    };

    const result = verifyCredential(vc as any, keys.publicKeyBytes);
    assert.ok(!result.valid);
    assert.ok(result.errors.some(e => /proof/i.test(e)));
  });

  it('detects tampered claims', () => {
    const keys = generateKeyPair();
    const issuerDid = createSelfDid(keys.publicKeyMultibase);
    const subjectDid = createSelfDid(generateKeyPair().publicKeyMultibase);

    const vc = createSelfSignedCredential(
      issuerDid,
      subjectDid,
      { role: 'assistant' },
      keys.privateKeyBytes
    );

    // Tamper with credential
    vc.credentialSubject['role'] = 'admin';

    const result = verifyCredential(vc, keys.publicKeyBytes);
    assert.ok(!result.valid);
  });
});

describe('End-to-End Roundtrip', () => {
  it('keygen → DID → resolve → sign → verify', async () => {
    // Step 1: Generate keys
    const orgKeys = generateKeyPair();
    const agentKeys = generateKeyPair();

    // Step 2: Create DIDs
    const orgDid = createOrgDid('ACME Corporation', orgKeys.publicKeyMultibase);
    const agentDid = createAgentDid('Sales Assistant', agentKeys.publicKeyMultibase);
    const selfDid = createSelfDid(orgKeys.publicKeyMultibase);

    // Step 3: Create DID Documents
    const orgDoc = createDidDocument(orgDid, orgKeys, { mode: 'org' });
    const agentDoc = createDidDocument(agentDid, agentKeys, {
      mode: 'agent',
      parentOrganization: orgDid,
      aiSystemType: 'agent',
    });

    assert.strictEqual(orgDoc.id, orgDid);
    assert.strictEqual(agentDoc['trail:parentOrganization'], orgDid);

    // Step 4: Resolve self DID (offline)
    const resolver = new TrailResolver();
    const resolved = await resolver.resolve(selfDid);
    assert.strictEqual(resolved.didDocument.id, selfDid);

    // Step 5: Create a Verifiable Credential
    const vc = createSelfSignedCredential(
      selfDid,
      agentDid,
      {
        name: 'Sales Assistant',
        parentOrganization: orgDid,
        aiSystemType: 'conversational-agent',
      },
      orgKeys.privateKeyBytes
    );

    // Step 6: Verify the credential
    const verification = verifyCredential(vc, orgKeys.publicKeyBytes);
    assert.ok(verification.valid, `VC verification failed: ${verification.errors.join(', ')}`);

    // Step 7: Verify proof directly
    const proof = vc.proof!;
    const vcWithoutProof = { ...vc };
    delete (vcWithoutProof as any).proof;
    const proofValid = verifyProof(vcWithoutProof, proof, orgKeys.publicKeyBytes);
    assert.ok(proofValid);

    console.log('✓ Full roundtrip: keygen → DID → resolve → VC sign → VC verify');
  });
});
