"use strict";
/**
 * JSON Canonicalization Scheme (JCS) — RFC 8785
 * https://www.rfc-editor.org/rfc/rfc8785
 *
 * Zero-dependency implementation for TRAIL Protocol.
 * Produces deterministic JSON output suitable for cryptographic signing.
 *
 * Key rules from RFC 8785:
 * 1. Object keys sorted by UTF-16 code unit order
 * 2. No whitespace between tokens
 * 3. Numbers serialized per ES2015 Number.toString() (IEEE 754)
 * 4. Strings use minimal escaping (\b, \f, \n, \r, \t, \\, \", and \uXXXX for < 0x20)
 * 5. null, true, false as literals
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.jcsCanonicalizeToString = jcsCanonicalizeToString;
exports.jcsCanonicalizeToBuffer = jcsCanonicalizeToBuffer;
/**
 * Serialize a string value per RFC 8785 §3.2.2.2.
 * Uses minimal JSON escaping: control chars below 0x20 get \uXXXX,
 * plus mandatory escapes for backslash and double-quote.
 */
function serializeString(value) {
    let result = '"';
    for (let i = 0; i < value.length; i++) {
        const ch = value.charCodeAt(i);
        if (ch === 0x08) {
            result += '\\b';
        }
        else if (ch === 0x09) {
            result += '\\t';
        }
        else if (ch === 0x0a) {
            result += '\\n';
        }
        else if (ch === 0x0c) {
            result += '\\f';
        }
        else if (ch === 0x0d) {
            result += '\\r';
        }
        else if (ch === 0x22) {
            result += '\\"';
        }
        else if (ch === 0x5c) {
            result += '\\\\';
        }
        else if (ch < 0x20) {
            result += '\\u' + ch.toString(16).padStart(4, '0');
        }
        else {
            result += value[i];
        }
    }
    result += '"';
    return result;
}
/**
 * Serialize a number per RFC 8785 §3.2.2.3.
 * Uses ES2015 Number.toString() which matches the IEEE 754 requirement.
 * Special cases: NaN and Infinity are not valid JSON → throw.
 */
function serializeNumber(value) {
    if (!Number.isFinite(value)) {
        throw new Error('JCS: NaN and Infinity are not valid JSON values');
    }
    // ES2015 Number.toString() produces the shortest representation
    // that uniquely identifies the IEEE 754 double — this is exactly
    // what RFC 8785 requires.
    return Object.is(value, -0) ? '0' : String(value);
}
/**
 * Compare two strings by UTF-16 code unit order per RFC 8785 §3.2.3.
 * This is the same as JavaScript's default string comparison.
 */
function compareKeys(a, b) {
    if (a < b)
        return -1;
    if (a > b)
        return 1;
    return 0;
}
/**
 * Canonicalize a JavaScript value per RFC 8785 (JCS).
 * Returns the canonical JSON string.
 */
function jcsCanonicalizeToString(value) {
    if (value === null)
        return 'null';
    if (value === undefined)
        return 'null'; // undefined → null in JSON
    switch (typeof value) {
        case 'boolean':
            return value ? 'true' : 'false';
        case 'number':
            return serializeNumber(value);
        case 'string':
            return serializeString(value);
        case 'object': {
            if (Array.isArray(value)) {
                return '[' + value.map(jcsCanonicalizeToString).join(',') + ']';
            }
            const obj = value;
            const keys = Object.keys(obj).sort(compareKeys);
            const entries = [];
            for (const key of keys) {
                const v = obj[key];
                if (v === undefined)
                    continue; // skip undefined properties
                entries.push(serializeString(key) + ':' + jcsCanonicalizeToString(v));
            }
            return '{' + entries.join(',') + '}';
        }
        default:
            throw new Error(`JCS: unsupported type "${typeof value}"`);
    }
}
/**
 * Canonicalize a JavaScript value to a UTF-8 Buffer per RFC 8785.
 * This is the form used for cryptographic signing.
 */
function jcsCanonicalizeToBuffer(value) {
    return Buffer.from(jcsCanonicalizeToString(value), 'utf-8');
}
