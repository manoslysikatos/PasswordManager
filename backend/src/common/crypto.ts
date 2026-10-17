import { createHash, createHmac, randomBytes, scrypt, type ScryptOptions, timingSafeEqual } from 'node:crypto';

// Server-side hashing of the login verifier. The verifier is already a 256-bit value derived in the
// browser (Argon2id -> HKDF), so the server never sees the master password. Hashing it again means a
// stolen database row cannot be replayed as a login ("pass-the-hash").
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 } as const;
const KEY_LENGTH = 32;

function scryptAsync(password: Buffer, salt: Buffer, options: ScryptOptions): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, KEY_LENGTH, options, (err, key) => (err ? reject(err) : resolve(key)));
  });
}

/** Stored format: scrypt$N$r$p$<salt base64>$<hash base64> */
export async function hashVerifier(verifier: string): Promise<string> {
  const salt = randomBytes(16);
  const { N, r, p } = SCRYPT_PARAMS;
  const key = await scryptAsync(Buffer.from(verifier, 'utf8'), salt, SCRYPT_PARAMS);
  return ['scrypt', N, r, p, salt.toString('base64'), key.toString('base64')].join('$');
}

export async function verifyVerifier(verifier: string, stored: string): Promise<boolean> {
  const [scheme, n, r, p, salt, hash] = stored.split('$');
  if (scheme !== 'scrypt' || !salt || !hash) return false;
  const expected = Buffer.from(hash, 'base64');
  const actual = await scryptAsync(Buffer.from(verifier, 'utf8'), Buffer.from(salt, 'base64'), {
    N: Number(n),
    r: Number(r),
    p: Number(p),
  });
  // Constant-time comparison: the response time does not reveal how many bytes matched.
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

let dummyHash: Promise<string> | undefined;
/** A real hash to check against when the user does not exist, so both paths take the same time. */
export function dummyVerifierHash(): Promise<string> {
  dummyHash ??= hashVerifier('dummy-verifier');
  return dummyHash;
}

/** 32 random bytes, URL-safe. Used for invitation links and refresh tokens. */
export function randomToken(): string {
  return randomBytes(32).toString('base64url');
}

/** Tokens are stored only as their SHA-256 hash: a leaked table does not hand out working tokens. */
export function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

/**
 * Deterministic fake Argon2 salt for an unknown email, so prelogin answers look the same for
 * existing and non-existing accounts (no account enumeration).
 */
export function fakeKdfSalt(serverSecret: string, email: string): string {
  return createHmac('sha256', serverSecret).update(`kdf-salt:${email}`).digest().subarray(0, 16).toString('base64');
}

/** Argon2id parameters returned for unknown emails. Must match what the browser uses for new accounts. */
export const DEFAULT_KDF_PARAMS = { version: 1, memory: 65536, iterations: 3, parallelism: 1 } as const;
