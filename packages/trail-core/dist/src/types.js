"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SUPPORTED_CRYPTOSUITES = void 0;
/**
 * Registry of supported cryptosuites and their metadata.
 * Used for crypto agility: implementations MUST support at least eddsa-jcs-2023,
 * and MAY support additional suites listed here.
 */
exports.SUPPORTED_CRYPTOSUITES = [
    {
        id: 'eddsa-jcs-2023',
        algorithm: 'Ed25519',
        canonicalization: 'JCS (RFC 8785)',
        keyType: 'OKP',
        status: 'active',
    },
];
