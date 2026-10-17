import { fakeKdfSalt, hashVerifier, randomToken, sha256, verifyVerifier } from './crypto.js';

describe('server-side crypto helpers', () => {
  it('accepts the right verifier and rejects a wrong one', async () => {
    const stored = await hashVerifier('correct-verifier');
    await expect(verifyVerifier('correct-verifier', stored)).resolves.toBe(true);
    await expect(verifyVerifier('wrong-verifier', stored)).resolves.toBe(false);
  });

  it('salts every hash, so the same verifier gives different stored values', async () => {
    expect(await hashVerifier('same')).not.toBe(await hashVerifier('same'));
  });

  it('rejects a malformed stored hash instead of throwing', async () => {
    await expect(verifyVerifier('x', 'not-a-hash')).resolves.toBe(false);
  });

  it('makes fake salts stable per email and different between emails', () => {
    expect(fakeKdfSalt('secret', 'a@x.com')).toBe(fakeKdfSalt('secret', 'a@x.com'));
    expect(fakeKdfSalt('secret', 'a@x.com')).not.toBe(fakeKdfSalt('secret', 'b@x.com'));
    expect(Buffer.from(fakeKdfSalt('secret', 'a@x.com'), 'base64')).toHaveLength(16);
  });

  it('creates 256-bit URL-safe tokens and hashes them', () => {
    const token = randomToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(sha256(token)).toMatch(/^[0-9a-f]{64}$/);
  });
});
