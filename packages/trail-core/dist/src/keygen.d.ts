import { KeyObject } from 'node:crypto';
import type { TrailKeyPair } from './types';
export declare function generateKeyPair(): TrailKeyPair;
export declare function publicKeyFromMultibase(multibase: string): Uint8Array;
export declare function createPrivateKeyObject(privateKeyBytes: Uint8Array): KeyObject;
export declare function createPublicKeyObject(publicKeyBytes: Uint8Array): KeyObject;
