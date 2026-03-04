"use strict";
// TRAIL Protocol Core SDK
// https://trailprotocol.org
// License: Apache-2.0
Object.defineProperty(exports, "__esModule", { value: true });
exports.SUPPORTED_CRYPTOSUITES = exports.jcsCanonicalizeToBuffer = exports.jcsCanonicalizeToString = exports.decodeMultibase = exports.encodeMultibase = exports.verifyCredential = exports.createSelfSignedCredential = exports.DEFAULT_CRYPTOSUITE = exports.isSupportedCryptosuite = exports.verifyProof = exports.createProof = exports.extractPublicKeyFromSelfDid = exports.TrailResolver = exports.SPEC_VERSION = exports.rotateKey = exports.createDidDocument = exports.computeTrailHash = exports.normalizeSlug = exports.parseTrailDid = exports.createAgentDid = exports.createOrgDid = exports.createSelfDid = exports.publicKeyFromMultibase = exports.generateKeyPair = void 0;
var keygen_1 = require("./keygen");
Object.defineProperty(exports, "generateKeyPair", { enumerable: true, get: function () { return keygen_1.generateKeyPair; } });
Object.defineProperty(exports, "publicKeyFromMultibase", { enumerable: true, get: function () { return keygen_1.publicKeyFromMultibase; } });
var did_1 = require("./did");
Object.defineProperty(exports, "createSelfDid", { enumerable: true, get: function () { return did_1.createSelfDid; } });
Object.defineProperty(exports, "createOrgDid", { enumerable: true, get: function () { return did_1.createOrgDid; } });
Object.defineProperty(exports, "createAgentDid", { enumerable: true, get: function () { return did_1.createAgentDid; } });
Object.defineProperty(exports, "parseTrailDid", { enumerable: true, get: function () { return did_1.parseTrailDid; } });
Object.defineProperty(exports, "normalizeSlug", { enumerable: true, get: function () { return did_1.normalizeSlug; } });
Object.defineProperty(exports, "computeTrailHash", { enumerable: true, get: function () { return did_1.computeTrailHash; } });
var document_1 = require("./document");
Object.defineProperty(exports, "createDidDocument", { enumerable: true, get: function () { return document_1.createDidDocument; } });
Object.defineProperty(exports, "rotateKey", { enumerable: true, get: function () { return document_1.rotateKey; } });
Object.defineProperty(exports, "SPEC_VERSION", { enumerable: true, get: function () { return document_1.SPEC_VERSION; } });
var resolver_1 = require("./resolver");
Object.defineProperty(exports, "TrailResolver", { enumerable: true, get: function () { return resolver_1.TrailResolver; } });
Object.defineProperty(exports, "extractPublicKeyFromSelfDid", { enumerable: true, get: function () { return resolver_1.extractPublicKeyFromSelfDid; } });
var proof_1 = require("./proof");
Object.defineProperty(exports, "createProof", { enumerable: true, get: function () { return proof_1.createProof; } });
Object.defineProperty(exports, "verifyProof", { enumerable: true, get: function () { return proof_1.verifyProof; } });
Object.defineProperty(exports, "isSupportedCryptosuite", { enumerable: true, get: function () { return proof_1.isSupportedCryptosuite; } });
Object.defineProperty(exports, "DEFAULT_CRYPTOSUITE", { enumerable: true, get: function () { return proof_1.DEFAULT_CRYPTOSUITE; } });
var credential_1 = require("./credential");
Object.defineProperty(exports, "createSelfSignedCredential", { enumerable: true, get: function () { return credential_1.createSelfSignedCredential; } });
Object.defineProperty(exports, "verifyCredential", { enumerable: true, get: function () { return credential_1.verifyCredential; } });
var base58_1 = require("./base58");
Object.defineProperty(exports, "encodeMultibase", { enumerable: true, get: function () { return base58_1.encodeMultibase; } });
Object.defineProperty(exports, "decodeMultibase", { enumerable: true, get: function () { return base58_1.decodeMultibase; } });
var jcs_1 = require("./jcs");
Object.defineProperty(exports, "jcsCanonicalizeToString", { enumerable: true, get: function () { return jcs_1.jcsCanonicalizeToString; } });
Object.defineProperty(exports, "jcsCanonicalizeToBuffer", { enumerable: true, get: function () { return jcs_1.jcsCanonicalizeToBuffer; } });
var types_1 = require("./types");
Object.defineProperty(exports, "SUPPORTED_CRYPTOSUITES", { enumerable: true, get: function () { return types_1.SUPPORTED_CRYPTOSUITES; } });
