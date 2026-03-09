/**
 * @aiir/verify — TypeScript declarations
 */

/** Produce canonical JSON encoding per AIIR SPEC.md §6 */
export declare function canonicalJson(obj: unknown): string;

/** Compute SHA-256 of a UTF-8 string (hex-encoded) */
export declare function sha256(str: string): Promise<string>;

/** Constant-time string comparison (timing side-channel safe) */
export declare function constantTimeEqual(a: string, b: string): boolean;

export interface VerifyResult {
  /** True if receipt passes all checks */
  valid: boolean;
  /** List of error messages (empty if valid) */
  errors: string[];
}

/** Verify an AIIR commit receipt per SPEC.md §9 */
export declare function verify(receipt: unknown): Promise<VerifyResult>;
