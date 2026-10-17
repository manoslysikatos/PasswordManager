import { randomBytes } from 'node:crypto';
import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module.js';
import { configureApp } from '../src/app.setup.js';
import { PrismaService } from '../src/prisma/prisma.service.js';
import { APP_TABLES } from './test-db.js';

// The full auth journey against the test database. The "keys" are random placeholders: the server
// never interprets them, it only stores and returns them (real crypto happens in the browser).
const b64 = (bytes = 32) => randomBytes(bytes).toString('base64');
const KDF = { version: 1, memory: 65536, iterations: 3, parallelism: 1 };

function keyMaterial() {
  return {
    publicKey: `pk.${b64(16)}`,
    encryptedPrivateKey: `v1.${b64(12)}.${b64(64)}`,
    kdfSalt: b64(16),
    kdfParams: KDF,
    authVerifier: b64(32),
  };
}
const personalVault = () => ({ encryptedVaultKey: `rsa.${b64(32)}`, orgEncryptedVaultKey: `rsa.${b64(32)}` });

function cookieValue(res: request.Response, name: string): string | undefined {
  const cookies = ([] as string[]).concat(res.get('Set-Cookie') ?? []);
  const cookie = cookies.find((c) => c.startsWith(`${name}=`));
  return cookie?.split(';')[0]?.slice(name.length + 1);
}

describe('Auth (e2e)', () => {
  let app: INestApplication<App>;
  let prisma: PrismaService;
  const admin = { email: 'eleni@example.com', name: 'Ελένη', ...keyMaterial() };
  const niki = { email: 'niki@example.com', name: 'Νίκη', ...keyMaterial() };

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication();
    configureApp(app);
    await app.init();
    prisma = app.get(PrismaService);
    await prisma.$executeRawUnsafe(`TRUNCATE TABLE ${APP_TABLES.map((t) => `"${t}"`).join(', ')} RESTART IDENTITY CASCADE`);
  });

  afterAll(async () => {
    await app.close();
  });

  const http = () => request(app.getHttpServer());

  describe('first-run setup', () => {
    it('reports that setup is needed on an empty database', async () => {
      await http().get('/setup/status').expect(200).expect({ needsSetup: true });
    });

    it('creates the first admin, the organization and the Admin role', async () => {
      await http()
        .post('/setup')
        .send({
          ...admin,
          email: 'Eleni@Example.com', // normalized to lower case
          organization: { name: 'Acme', publicKey: `orgpk.${b64(16)}`, encryptedOrgPrivateKey: `v1.${b64(12)}.${b64(64)}` },
          personalVault: personalVault(),
        })
        .expect(201);

      const user = await prisma.user.findUniqueOrThrow({
        where: { email: admin.email },
        include: { roles: { include: { role: { include: { permissions: true } } } }, orgKeyGrant: true, vaultKeys: true },
      });
      expect(user.status).toBe('ACTIVE');
      expect(user.authVerifierHash).toMatch(/^scrypt\$/); // never the verifier itself
      expect(user.authVerifierHash).not.toContain(admin.authVerifier);
      expect(user.orgKeyGrant).not.toBeNull();
      expect(user.vaultKeys).toHaveLength(1); // personal vault
      expect(user.roles[0]?.role.permissions.map((p) => p.permission)).toContain('ORG_ADMIN');
    });

    it('refuses a second setup', async () => {
      await http()
        .post('/setup')
        .send({ ...keyMaterial(), email: 'x@example.com', name: 'X', organization: { name: 'B', publicKey: 'p', encryptedOrgPrivateKey: 'k' }, personalVault: personalVault() })
        .expect(409);
    });
  });

  describe('prelogin and login', () => {
    it('returns the real salt for an existing user', async () => {
      const res = await http().post('/auth/prelogin').send({ email: admin.email }).expect(200);
      expect(res.body).toEqual({ kdfSalt: admin.kdfSalt, kdfParams: KDF });
    });

    it('returns a stable fake salt for an unknown email (no account enumeration)', async () => {
      const first = await http().post('/auth/prelogin').send({ email: 'nobody@example.com' }).expect(200);
      const second = await http().post('/auth/prelogin').send({ email: 'nobody@example.com' }).expect(200);
      const other = await http().post('/auth/prelogin').send({ email: 'someone@example.com' }).expect(200);
      expect(first.body).toEqual(second.body);
      expect(first.body.kdfSalt).not.toBe(other.body.kdfSalt);
      expect(Object.keys(first.body).sort()).toEqual(['kdfParams', 'kdfSalt']);
    });

    it('rejects a wrong verifier with a generic message', async () => {
      const res = await http().post('/auth/login').send({ email: admin.email, authVerifier: b64(32) }).expect(401);
      expect(res.body.message).toBe('Invalid email or password');
      const unknown = await http().post('/auth/login').send({ email: 'nobody@example.com', authVerifier: b64(32) }).expect(401);
      expect(unknown.body.message).toBe(res.body.message);
    });

    it('rejects unknown fields and malformed input', async () => {
      await http().post('/auth/login').send({ email: admin.email, authVerifier: admin.authVerifier, isAdmin: true }).expect(400);
      await http().post('/auth/login').send({ email: 'not-an-email', authVerifier: admin.authVerifier }).expect(400);
    });

    it('logs in with httpOnly cookies and returns the locked private key', async () => {
      const agent = request.agent(app.getHttpServer());
      const res = await agent.post('/auth/login').send({ email: admin.email, authVerifier: admin.authVerifier }).expect(200);
      expect(res.body.encryptedPrivateKey).toBe(admin.encryptedPrivateKey);
      const cookies = ([] as string[]).concat(res.get('Set-Cookie') ?? []);
      expect(cookies.every((c) => /HttpOnly/i.test(c) && /SameSite=Strict/i.test(c))).toBe(true);

      const me = await agent.get('/auth/me').expect(200);
      expect(me.body.email).toBe(admin.email);
      expect(me.body.permissions).toEqual(expect.arrayContaining(['MANAGE_USERS', 'ORG_ADMIN']));
    });
  });

  describe('invitations and registration', () => {
    let inviteToken: string;

    it('requires a session to invite', async () => {
      await http().post('/invitations').send({ email: niki.email, name: niki.name }).expect(401);
    });

    it('lets an admin invite a user with roles', async () => {
      const marketing = await prisma.role.create({ data: { name: 'Marketing' } });
      const agent = request.agent(app.getHttpServer());
      await agent.post('/auth/login').send({ email: admin.email, authVerifier: admin.authVerifier }).expect(200);

      const res = await agent.post('/invitations').send({ email: niki.email, name: niki.name, roleIds: [marketing.id] }).expect(201);
      expect(res.body.inviteUrl).toMatch(/\/invite\/[A-Za-z0-9_-]{43}$/);
      inviteToken = res.body.inviteUrl.split('/').pop();

      const stored = await prisma.invitation.findFirstOrThrow({ where: { user: { email: niki.email } } });
      expect(stored.tokenHash).not.toBe(inviteToken); // only the hash is stored
    });

    it('shows the invitation and the organization public key', async () => {
      const res = await http().get(`/invitations/${inviteToken}`).expect(200);
      expect(res.body).toMatchObject({ email: niki.email, name: niki.name, organization: { name: 'Acme' } });
    });

    it('registers once, and the link cannot be reused', async () => {
      await http().post('/auth/register').send({ token: inviteToken, ...keyMaterial(), ...pick(niki), personalVault: personalVault() }).expect(201);
      await http().post('/auth/register').send({ token: inviteToken, ...keyMaterial(), personalVault: personalVault() }).expect(400);
      await http().get(`/invitations/${inviteToken}`).expect(400);
    });

    it('a user without MANAGE_USERS cannot invite', async () => {
      const agent = request.agent(app.getHttpServer());
      await agent.post('/auth/login').send({ email: niki.email, authVerifier: niki.authVerifier }).expect(200);
      const me = await agent.get('/auth/me').expect(200);
      expect(me.body.permissions).toEqual([]); // Marketing has no action permissions
      await agent.post('/invitations').send({ email: 'other@example.com', name: 'Other' }).expect(403);
    });
  });

  describe('sessions: refresh rotation and logout', () => {
    it('rotates the refresh token, and reusing an old one ends every session', async () => {
      const agent = request.agent(app.getHttpServer());
      const login = await agent.post('/auth/login').send({ email: admin.email, authVerifier: admin.authVerifier }).expect(200);
      const firstRefresh = cookieValue(login, 'pm_refresh');
      expect(firstRefresh).toBeDefined();

      const rotated = await agent.post('/auth/refresh').expect(204);
      expect(cookieValue(rotated, 'pm_refresh')).not.toBe(firstRefresh);

      // Someone replays the old token: rejected, and the current session is revoked too.
      await http().post('/auth/refresh').set('Cookie', `pm_refresh=${firstRefresh}`).expect(401);
      await agent.post('/auth/refresh').expect(401);
    });

    it('logout revokes the refresh token and clears the cookies', async () => {
      const agent = request.agent(app.getHttpServer());
      await agent.post('/auth/login').send({ email: admin.email, authVerifier: admin.authVerifier }).expect(200);
      const out = await agent.post('/auth/logout').expect(204);
      expect(cookieValue(out, 'pm_access')).toBe('');
      await agent.post('/auth/refresh').expect(401);
      await agent.get('/auth/me').expect(401);
    });

    it('a deactivated user loses access immediately', async () => {
      const agent = request.agent(app.getHttpServer());
      await agent.post('/auth/login').send({ email: niki.email, authVerifier: niki.authVerifier }).expect(200);
      await prisma.user.update({ where: { email: niki.email }, data: { status: 'DEACTIVATED' } });
      await agent.get('/auth/me').expect(401);
    });

    it('records logins and failures in the audit log', async () => {
      const actions = (await prisma.auditLog.findMany({ select: { action: true } })).map((a) => a.action);
      expect(actions).toEqual(expect.arrayContaining(['LOGIN', 'LOGIN_FAILED', 'LOGOUT', 'USER_INVITED', 'USER_ACTIVATED']));
    });
  });
});

/** Registration uses Niki's own key material, so she can log in with her verifier afterwards. */
function pick(user: { publicKey: string; encryptedPrivateKey: string; kdfSalt: string; kdfParams: typeof KDF; authVerifier: string }) {
  const { publicKey, encryptedPrivateKey, kdfSalt, kdfParams, authVerifier } = user;
  return { publicKey, encryptedPrivateKey, kdfSalt, kdfParams, authVerifier };
}
