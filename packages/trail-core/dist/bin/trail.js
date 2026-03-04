#!/usr/bin/env node
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
const fs = __importStar(require("node:fs"));
const keygen_1 = require("../src/keygen");
const did_1 = require("../src/did");
const document_1 = require("../src/document");
const resolver_1 = require("../src/resolver");
const credential_1 = require("../src/credential");
const base58_1 = require("../src/base58");
const args = process.argv.slice(2);
const command = args[0];
const subcommand = args[1];
function getFlag(name) {
    const idx = args.indexOf(`--${name}`);
    if (idx === -1 || idx + 1 >= args.length)
        return undefined;
    return args[idx + 1];
}
function printJson(obj) {
    console.log(JSON.stringify(obj, null, 2));
}
function printUsage() {
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
async function main() {
    if (!command || command === 'help' || command === '--help') {
        printUsage();
        process.exit(0);
    }
    if (command === 'keygen') {
        const keys = (0, keygen_1.generateKeyPair)();
        const output = {
            publicKeyJwk: keys.publicKeyJwk,
            publicKeyMultibase: keys.publicKeyMultibase,
            privateKeyBase64: Buffer.from(keys.privateKeyBytes).toString('base64'),
            selfDid: (0, did_1.createSelfDid)(keys.publicKeyMultibase),
        };
        const outFile = getFlag('output');
        if (outFile) {
            fs.writeFileSync(outFile, JSON.stringify(output, null, 2));
            console.log(`Keypair written to ${outFile}`);
            console.log(`Self DID: ${output.selfDid}`);
        }
        else {
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
                const publicKeyBytes = (0, base58_1.decodeMultibase)(keyData.publicKeyMultibase);
                keys = {
                    publicKeyBytes,
                    privateKeyBytes: new Uint8Array(privateKeyBytes),
                    publicKeyJwk: keyData.publicKeyJwk,
                    publicKeyMultibase: keyData.publicKeyMultibase,
                };
            }
            else {
                keys = (0, keygen_1.generateKeyPair)();
            }
            let did;
            if (mode === 'self') {
                did = (0, did_1.createSelfDid)(keys.publicKeyMultibase);
            }
            else if (mode === 'org') {
                const subject = getFlag('subject');
                if (!subject) {
                    console.error('Error: --subject required for org mode');
                    process.exit(1);
                }
                did = (0, did_1.createOrgDid)(subject, keys.publicKeyMultibase);
            }
            else {
                const subject = getFlag('subject');
                const parent = getFlag('parent');
                if (!subject) {
                    console.error('Error: --subject required for agent mode');
                    process.exit(1);
                }
                did = (0, did_1.createAgentDid)(subject, keys.publicKeyMultibase);
                const doc = (0, document_1.createDidDocument)(did, keys, {
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
            const doc = (0, document_1.createDidDocument)(did, keys, { mode: mode });
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
            const resolver = new resolver_1.TrailResolver();
            try {
                const result = await resolver.resolve(did);
                printJson(result);
            }
            catch (err) {
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
            const vc = (0, credential_1.createSelfSignedCredential)(issuer, subject, claims, privateKeyBytes);
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
            const publicKeyBytes = (0, base58_1.decodeMultibase)(keyData.publicKeyMultibase);
            const result = (0, credential_1.verifyCredential)(vc, publicKeyBytes);
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
