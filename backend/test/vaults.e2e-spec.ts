import { randomBytes } from 'node:crypto';
import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module.js';
import { configureApp } from '../src/app.setup.js';
import { hashVerifier } from '../src/common/crypto.js';
import { Permission } from '../src/generated/prisma/client.js';
import { PrismaService } from '../src/prisma/prisma.service.js';
import { APP_TABLES } from './test-db.js';

// Groups (shared vaults), connecting them to roles, and the pending keys mechanism.
// The cast: Eleni (admin, holds the org key), Nikos (team lead, CREATE_GROUPS), Maria (HR, MANAGE_USERS),
// Vasilis and Kostas (developers), Niki and Petros (invited, register later).
const b64 = (bytes = 32) => randomBytes(bytes).toString('base64');
const KDF = { version: 1, memory: 65536, iterations: 3, parallelism: 1 };
const lockedKey = () => `rsa.${b64()}`;

type TestUser = { id: string; email: string; authVerifier: string };

describe('Vaults and pending keys (e2e)', () => {
  let app: INestApplication<App>;
  let prisma: PrismaService;
  const roles: Record<string, string> = {};
  const as: Record<string, ReturnType<typeof request.agent>> = {};
  let eleni: TestUser, nikos: TestUser, maria: TestUser, vasilis: TestUser, kostas: TestUser, niki: TestUser, petros: TestUser;
  let vaultId: string;

  async function createUser(email: string, opts: { invited?: boolean; roleIds?: string[] } = {}): Promise<TestUser> {
    const authVerifier = b64();
    const user = await prisma.user.create({
      data: opts.invited
        ? { email, name: email, status: 'INVITED' }
        : { email, name: email, status: 'ACTIVE', ...(await keyMaterial(authVerifier)) },
    });
    for (const roleId of opts.roleIds ?? []) await prisma.userRole.create({ data: { userId: user.id, roleId } });
    return { id: user.id, email, authVerifier };
  }
  async function keyMaterial(authVerifier: string) {
    return {
      publicKey: `pk.${b64(16)}`,
      encryptedPrivateKey: `v1.${b64(12)}.${b64(64)}`,
      kdfSalt: b64(16),
      kdfParams: KDF,
      authVerifierHash: await hashVerifier(authVerifier),
    };
  }
  /** What the registration endpoint does, minus the invitation: the user now has a public key. */
  async function register(user: TestUser) {
    await prisma.user.update({ where: { id: user.id }, data: { status: 'ACTIVE', ...(await keyMaterial(user.authVerifier)) } });
  }
  async function signIn(user: TestUser) {
    const agent = request.agent(app.getHttpServer());
    await agent.post('/auth/login').send({ email: user.email, authVerifier: user.authVerifier }).expect(200);
    return agent;
  }

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication();
    configureApp(app);
    await app.init();
    prisma = app.get(PrismaService);
    await prisma.$executeRawUnsafe(`TRUNCATE TABLE ${APP_TABLES.map((t) => `"${t}"`).join(', ')} RESTART IDENTITY CASCADE`);

    const role = async (name: string, permissions: Permission[]) =>
      (await prisma.role.create({ data: { name, permissions: { create: permissions.map((permission) => ({ permission })) } } })).id;
    roles.admin = await role('Admin', Object.values(Permission));
    roles.lead = await role('Team Lead', ['CREATE_GROUPS']);
    roles.hr = await role('HR', ['MANAGE_USERS']);
    roles.devs = await role('Developers', []);

    eleni = await createUser('eleni@example.com', { roleIds: [roles.admin] });
    await prisma.orgKeyGrant.create({ data: { userId: eleni.id, encryptedOrgPrivateKey: lockedKey(), grantedById: eleni.id } });
    nikos = await createUser('nikos@example.com', { roleIds: [roles.lead] });
    maria = await createUser('maria@example.com', { roleIds: [roles.hr] });
    vasilis = await createUser('vasilis@example.com');
    kostas = await createUser('kostas@example.com');
    niki = await createUser('niki@example.com', { invited: true });
    petros = await createUser('petros@example.com', { invited: true });
    for (const [name, user] of Object.entries({ eleni, nikos, maria, vasilis })) as[name] = await signIn(user);
  });

  afterAll(async () => {
    await app.close();
  });

  describe('creating and listing groups', () => {
    it('needs CREATE_GROUPS', async () => {
      await as.vasilis!.post('/vaults').send({ name: 'Mine', encryptedVaultKey: lockedKey(), orgEncryptedVaultKey: lockedKey() }).expect(403);
    });

    it('creates a shared vault owned by its creator', async () => {
      const res = await as.nikos!.post('/vaults').send({ name: 'Dev servers', encryptedVaultKey: lockedKey(), orgEncryptedVaultKey: lockedKey() }).expect(201);
      expect(res.body).toMatchObject({ name: 'Dev servers', type: 'SHARED' });
      vaultId = res.body.id;
      const mine = await as.nikos!.get('/vaults').expect(200);
      expect(mine.body).toEqual([expect.objectContaining({ id: vaultId, accessLevel: 'OWNER', encryptedVaultKey: expect.stringMatching(/^rsa\./) })]);
    });

    it('shows every vault, with the org-locked key, only to org admins', async () => {
      await as.nikos!.get('/vaults/all').expect(403);
      const all = await as.eleni!.get('/vaults/all').expect(200);
      expect(all.body[0]).toMatchObject({ id: vaultId, owner: { id: nikos.id }, orgEncryptedVaultKey: expect.stringMatching(/^rsa\./), roles: [] });
    });

    it('can be renamed by its owner, not by others', async () => {
      await as.vasilis!.patch(`/vaults/${vaultId}`).send({ name: 'Hacked' }).expect(403);
      await as.nikos!.patch(`/vaults/${vaultId}`).send({ name: 'Dev Servers' }).expect(200);
    });
  });

  describe('connecting a group to a role', () => {
    it('HR gives Vasilis the Developers role before the group is connected', async () => {
      const res = await as.maria!.post(`/users/${vasilis.id}/roles`).send({ roleId: roles.devs }).expect(201);
      expect(res.body.keysPending).toBe(false); // the role opens nothing yet
    });

    it('the owner connects the group and gets the keys to lock, one per member', async () => {
      const res = await as.nikos!.post(`/vaults/${vaultId}/roles`).send({ roleId: roles.devs, accessLevel: 'EDITOR' }).expect(201);
      expect(res.body.keyRequests).toEqual([
        expect.objectContaining({ vaultId, roleId: roles.devs, userId: vasilis.id, accessLevel: 'EDITOR', publicKey: expect.stringMatching(/^pk\./) }),
      ]);
      await as.nikos!.post(`/vaults/${vaultId}/roles`).send({ roleId: roles.devs, accessLevel: 'VIEWER' }).expect(409);
      await as.maria!.post(`/vaults/${vaultId}/roles`).send({ roleId: roles.hr, accessLevel: 'VIEWER' }).expect(403);
    });

    it('a personal vault is never shared with a role', async () => {
      const personal = await prisma.vault.create({ data: { name: 'Personal', type: 'PERSONAL', ownerId: eleni.id, orgEncryptedVaultKey: lockedKey() } });
      await as.eleni!.post(`/vaults/${personal.id}/roles`).send({ roleId: roles.devs, accessLevel: 'VIEWER' }).expect(400);
    });
  });

  describe('pending keys', () => {
    it('are listed to whoever can lock them, and to nobody else', async () => {
      const forNikos = await as.nikos!.get('/keys/pending').expect(200);
      expect(forNikos.body.vaultKeys.map((k: { userId: string }) => k.userId)).toEqual([vasilis.id]);
      expect(forNikos.body.orgKeys).toEqual([]);
      const forEleni = await as.eleni!.get('/keys/pending').expect(200); // the org key opens every vault
      expect(forEleni.body.vaultKeys).toHaveLength(1);
      for (const agent of [as.maria!, as.vasilis!]) {
        expect((await agent.get('/keys/pending').expect(200)).body).toEqual({ vaultKeys: [], orgKeys: [] });
      }
    });

    it('can only be fulfilled by someone who can see them, and only once', async () => {
      const key = { vaultId, userId: vasilis.id, roleId: roles.devs, encryptedVaultKey: lockedKey() };
      await as.maria!.post('/keys/pending').send({ vaultKeys: [key] }).expect(400);
      expect((await as.nikos!.post('/keys/pending').send({ vaultKeys: [key] }).expect(201)).body).toEqual({ vaultKeys: 1, orgKeys: 0 });
      await as.nikos!.post('/keys/pending').send({ vaultKeys: [key] }).expect(400);

      const mine = await as.vasilis!.get('/vaults').expect(200);
      expect(mine.body).toEqual([expect.objectContaining({ id: vaultId, accessLevel: 'EDITOR' })]);
    });

    it('wait for a user who has not registered yet', async () => {
      const res = await as.maria!.post(`/users/${niki.id}/roles`).send({ roleId: roles.devs }).expect(201);
      expect(res.body.keysPending).toBe(true);
      expect((await as.nikos!.get('/keys/pending').expect(200)).body.vaultKeys).toEqual([]); // no public key to lock with

      await register(niki);
      const pending = await as.nikos!.get('/keys/pending').expect(200);
      expect(pending.body.vaultKeys).toEqual([expect.objectContaining({ userId: niki.id })]);
      await as.nikos!.post('/keys/pending').send({ vaultKeys: [{ vaultId, userId: niki.id, roleId: roles.devs, encryptedVaultKey: lockedKey() }] }).expect(201);
    });

    it('wait when the person giving the role cannot open the group', async () => {
      await as.maria!
        .post(`/users/${kostas.id}/roles`)
        .send({ roleId: roles.devs, vaultKeys: [{ vaultId, encryptedVaultKey: lockedKey() }] })
        .expect(403); // HR does not hold the vault key
      const res = await as.maria!.post(`/users/${kostas.id}/roles`).send({ roleId: roles.devs }).expect(201);
      expect(res.body.keysPending).toBe(true);
      expect((await as.nikos!.get('/keys/pending').expect(200)).body.vaultKeys).toEqual([expect.objectContaining({ userId: kostas.id })]);
    });

    it('include the organization key for a new org admin, visible only to org-key holders', async () => {
      const res = await as.eleni!.post(`/users/${petros.id}/roles`).send({ roleId: roles.admin }).expect(201);
      expect(res.body.keysPending).toBe(true);
      await register(petros);

      expect((await as.nikos!.get('/keys/pending').expect(200)).body.orgKeys).toEqual([]);
      const forEleni = await as.eleni!.get('/keys/pending').expect(200);
      expect(forEleni.body.orgKeys).toEqual([expect.objectContaining({ userId: petros.id, publicKey: expect.stringMatching(/^pk\./) })]);
      await as.eleni!.post('/keys/pending').send({ orgKeys: [{ userId: petros.id, encryptedOrgPrivateKey: lockedKey() }] }).expect(201);
      expect(await prisma.orgKeyGrant.findUnique({ where: { userId: petros.id } })).toMatchObject({ grantedById: eleni.id });
    });
  });

  describe('changing and removing a role\'s access', () => {
    it('switches the members between editor and viewer', async () => {
      await as.nikos!.patch(`/vaults/${vaultId}/roles/${roles.devs}`).send({ accessLevel: 'VIEWER' }).expect(200);
      const levels = await prisma.vaultKey.findMany({ where: { vaultId, viaRoleId: roles.devs }, select: { accessLevel: true } });
      expect(levels.map((k) => k.accessLevel)).toEqual(['VIEWER', 'VIEWER']); // Vasilis and Niki; Kostas still pending
      await as.nikos!.patch(`/vaults/${vaultId}/roles/${roles.hr}`).send({ accessLevel: 'VIEWER' }).expect(404);
    });

    it('revoking deletes the members\' keys and lists the credentials they saw', async () => {
      const credentials = [];
      for (const title of ['GitLab', 'Jenkins']) {
        credentials.push(
          await prisma.credential.create({
            data: { vaultId, title, encryptedItemKey: lockedKey(), encryptedPassword: `v1.${b64(12)}.${b64()}`, createdById: nikos.id },
          }),
        );
      }
      // Vasilis also has GitLab shared with him directly, so he keeps it.
      await prisma.credentialShare.create({
        data: { credentialId: credentials[0]!.id, userId: vasilis.id, encryptedItemKey: lockedKey(), accessLevel: 'VIEWER', grantedById: nikos.id },
      });

      const res = await as.nikos!.delete(`/vaults/${vaultId}/roles/${roles.devs}`).expect(200);
      expect(res.body.rotationTasks).toBe(3); // Vasilis: Jenkins · Niki: both · Kostas never had a key
      expect(await prisma.vaultKey.count({ where: { vaultId, viaRoleId: roles.devs } })).toBe(0);
      expect(await prisma.vaultKey.count({ where: { vaultId, userId: nikos.id } })).toBe(1); // the owner keeps it
      expect((await as.vasilis!.get('/vaults').expect(200)).body).toEqual([]);
      expect((await as.nikos!.get('/keys/pending').expect(200)).body.vaultKeys).toEqual([]); // Kostas' request is gone too
    });

    it('records group changes in the audit log', async () => {
      const actions = (await prisma.auditLog.findMany({ select: { action: true } })).map((a) => a.action);
      expect(actions).toEqual(expect.arrayContaining(['VAULT_CREATED', 'VAULT_UPDATED', 'VAULT_SHARED', 'KEYS_GRANTED', 'VAULT_ACCESS_REVOKED']));
    });
  });
});
