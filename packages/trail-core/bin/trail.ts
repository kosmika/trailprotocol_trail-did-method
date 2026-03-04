#!/usr/bin/env node

import * as fs from 'node:fs';
import { generateKeyPair } from '../src/keygen';
import { createSelfDid, createOrgDid, createAgentDid, parseTrailDid } from '../src/did';
import { createDidDocument } from '../src/document';
import { TrailResolver } from '../src/resolver';
import { createSelfSignedCredential, verifyCredential } from '../src/credential';
import { decodeMultibase } from '../src/base58';

const args = process.argv.slice(2);
const command = args[0];
const subcommand = args[1];

function getFlag(name: string): string | undefined {
  const idx = args.indexOf(`--${name}`);
  if (idx === -1 || idx + 1 >= args.length) return undefined;
  return args[idx + 1];
}

function printJson(obj: unknown): void {
  console.log(JSON.stringify(obj, null, 2));
}

function printUsage(): void {
  console.log(`
TRAIL Protocol CLI v0.1.0
https://trailprotocol.org

Usage:
  trail keygen [--output <file>]
    Generate an Ed25519 keypair for TRAIL identity.

  trail did create --mode <self|org|agent> [--subject <name>] [--parent <did>]
    Create a DID and DID Document.
    --mode self    Local Verification Mode (no registry needed)
    --mode org     Organization identity (requires --subject)
    --mode agent   AI Agent identity (requires --subject, --parent)

  trail did resolve <did>
    Resolve a DID. Self-mode DIDs are resolved locally.

  trail vc create --issuer <did> --subject <did> --claims <json> --key <keyfile>
    Create a self-signed Verifiable Credential.

  trail vc verify <vc-file> --key <keyfile>
    Verify a Verifiable Credential.

Examples:
  trail keygen
  trail keygen --output keys.json
  trail did create --mode self
  trail did create --mode org --subject "ACME Corporation GmbH"
  trail did resolve did:trail:self:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
`);
}

async function main(): Promise<void> {
  if (!command || command === 'help' || command === '--help') {
    printUsage();
    process.exit(0);
  }

  if (command === 'keygen') {
    const keys = generateKeyPair();
    const output = {
      publicKeyJwk: keys.publicKeyJwk,
      publicKeyMultibase: keys.publicKeyMultibase,
      privateKeyBase64: Buffer.from(keys.privateKeyBytes).toString('base64'),
      selfDid: createSelfDid(keys.publicKeyMultibase),
    };

    const outFile = getFlag('output');
    if (outFile) {
      fs.writeFileSync(outFile, JSON.stringify(output, null, 2));
      console.log(`Keypair written to ${outFile}`);
      console.log(`Self DID: ${output.selfDid}`);
    } else {
      printJson(output);
    }
    return;
  }

  if (command === 'did') {
    if (subcommand === 'create') {
      const mode = getFlag('mode');
      if (!mode || !['self', 'org', 'agent'].includes(mode)) {
        console.error('Error: --mode must be self, org, or agent');
        process.exit(1);
      }

      // Load or generate keys
      const keyFile = getFlag('key');
      let keys;
      if (keyFile) {
        const keyData = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
        const { generateKeyPair: gen } = require('../src/keygen');
        // Reconstruct from saved key
        const privateKeyBytes = Buffer.from(keyData.privateKeyBase64, 'base64');
        const publicKeyBytes = decodeMultibase(keyData.publicKeyMultibase);
        keys = {
          publicKeyBytes,
          privateKeyBytes: new Uint8Array(privateKeyBytes),
          publicKeyJwk: keyData.publicKeyJwk,
          publicKeyMultibase: keyData.publicKeyMultibase,
        };
      } else {
        keys = generateKeyPair();
      }

      let did: string;
      if (mode === 'self') {
        did = createSelfDid(keys.publicKeyMultibase);
      } else if (mode === 'org') {
        const subject = getFlag('subject');
        if (!subject) {
          console.error('Error: --subject required for org mode');
          process.exit(1);
        }
        did = createOrgDid(subject, keys.publicKeyMultibase);
      } else {
        const subject = getFlag('subject');
        const parent = getFlag('parent');
        if (!subject) {
          console.error('Error: --subject required for agent mode');
          process.exit(1);
        }
        did = createAgentDid(subject, keys.publicKeyMultibase);
        const doc = createDidDocument(did, keys, {
          mode: 'agent',
          parentOrganization: parent,
          aiSystemType: 'agent',
        });
        printJson({
          did,
          didDocument: doc,
          keyPair: keyFile ? undefined : {
            publicKeyJwk: keys.publicKeyJwk,
            publicKeyMultibase: keys.publicKeyMultibase,
            privateKeyBase64: Buffer.from(keys.privateKeyBytes).toString('base64'),
          },
        });
        return;
      }

      const doc = createDidDocument(did, keys, { mode: mode as any });
      printJson({
        did,
        didDocument: doc,
        keyPair: keyFile ? undefined : {
          publicKeyJwk: keys.publicKeyJwk,
          publicKeyMultibase: keys.publicKeyMultibase,
          privateKeyBase64: Buffer.from(keys.privateKeyBytes).toString('base64'),
        },
      });
      return;
    }

    if (subcommand === 'resolve') {
      const did = args[2];
      if (!did) {
        console.error('Error: provide a DID to resolve');
        process.exit(1);
      }

      const resolver = new TrailResolver();
      try {
        const result = await resolver.resolve(did);
        printJson(result);
      } catch (err: any) {
        console.error(`Resolution failed: ${err.message}`);
        process.exit(1);
      }
      return;
    }

    console.error('Unknown did subcommand. Use: create, resolve');
    process.exit(1);
  }

  if (command === 'vc') {
    if (subcommand === 'create') {
      const issuer = getFlag('issuer');
      const subject = getFlag('subject');
      const claimsJson = getFlag('claims');
      const keyFile = getFlag('key');

      if (!issuer || !subject || !claimsJson || !keyFile) {
        console.error('Error: --issuer, --subject, --claims, and --key are all required');
        process.exit(1);
      }

      const keyData = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
      const privateKeyBytes = new Uint8Array(Buffer.from(keyData.privateKeyBase64, 'base64'));
      const claims = JSON.parse(claimsJson);

      const vc = createSelfSignedCredential(issuer, subject, claims, privateKeyBytes);
      printJson(vc);
      return;
    }

    if (subcommand === 'verify') {
      const vcFile = args[2];
      const keyFile = getFlag('key');

      if (!vcFile || !keyFile) {
        console.error('Error: provide a VC file and --key <keyfile>');
        process.exit(1);
      }

      const vc = JSON.parse(fs.readFileSync(vcFile, 'utf-8'));
      const keyData = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
      const publicKeyBytes = decodeMultibase(keyData.publicKeyMultibase);

      const result = verifyCredential(vc, publicKeyBytes);
      printJson(result);
      process.exit(result.valid ? 0 : 1);
      return;
    }

    console.error('Unknown vc subcommand. Use: create, verify');
    process.exit(1);
  }

  console.error(`Unknown command: ${command}`);
  printUsage();
  process.exit(1);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
