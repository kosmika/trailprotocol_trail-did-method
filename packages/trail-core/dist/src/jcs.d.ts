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
/**
 * Canonicalize a JavaScript value per RFC 8785 (JCS).
 * Returns the canonical JSON string.
 */
export declare function jcsCanonicalizeToString(value: unknown): string;
/**
 * Canonicalize a JavaScript value to a UTF-8 Buffer per RFC 8785.
 * This is the form used for cryptographic signing.
 */
export declare function jcsCanonicalizeToBuffer(value: unknown): Buffer;
