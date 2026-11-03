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

// Roles, assignments and what they do to keys. Users are created straight in the database (with a real
// verifier hash, so they can log in); vaults and credentials too, since their API does not exist yet.
const b64 = (bytes = 32) => randomBytes(bytes).toString('base64');
const KDF = { version: 1, memory: 65536, iterations: 3, parallelism: 1 };

describe('Roles and assignments (e2e)', () => {
  let app: INestApplication<App>;
  let prisma: PrismaService;
  const ids: Record<string, string> = {};

  const http = () => request(app.getHttpServer());
  async function signIn(email: string, authVerifier: string) {
    const agent = request.agent(app.getHttpServer());
    await agent.post('/auth/login').send({ email, authVerifier }).expect(200);
    return agent;
  }
  async function createUser(email: string, opts: { invited?: boolean; roleIds?: string[] } = {}) {
    const authVerifier = b64();
    const user = await prisma.user.create({
      data: opts.invited
        ? { email, name: email, status: 'INVITED' }
        : {
            email,
            name: email,
            status: 'ACTIVE',
            publicKey: `pk.${b64(16)}`,
            encryptedPrivateKey: `v1.${b64(12)}.${b64(64)}`,
            kdfSalt: b64(16),
            kdfParams: KDF,
            authVerifierHash: await hashVerifier(authVerifier),
          },
    });
    for (const roleId of opts.roleIds ?? []) await prisma.userRole.create({ data: { userId: user.id, roleId } });
    return { id: user.id, email, authVerifier };
  }
  async function vaultWithCredentials(name: string, ownerId: string, count: number, type: 'SHARED' | 'PERSONAL' = 'SHARED') {
    const vault = await prisma.vault.create({ data: { name, type, ownerId, orgEncryptedVaultKey: `rsa.${b64()}` } });
    const credentials = [];
    for (let i = 0; i < count; i++) {
      credentials.push(
        await prisma.credential.create({
          data: { vaultId: vault.id, title: `${name} ${i}`, encryptedItemKey: `v1.${b64(12)}.${b64()}`, encryptedPassword: `v1.${b64(12)}.${b64()}`, createdById: ownerId },
        }),
      );
    }
    return { vault, credentials };
  }

  let admin: Awaited<ReturnType<typeof createUser>>;
  let hr: Awaited<ReturnType<typeof createUser>>;
  let dev: Awaited<ReturnType<typeof createUser>>;
  let newbie: Awaited<ReturnType<typeof createUser>>;
  let adminAgent: ReturnType<typeof request.agent>;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication();
    configureApp(app);
    await app.init();
    prisma = app.get(PrismaService);
    await prisma.$executeRawUnsafe(`TRUNCATE TABLE ${APP_TABLES.map((t) => `"${t}"`).join(', ')} RESTART IDENTITY CASCADE`);

    const adminRole = await prisma.role.create({
      data: { name: 'Admin', permissions: { create: Object.values(Permission).map((permission) => ({ permission })) } },
    });
    const hrRole = await prisma.role.create({ data: { name: 'HR', permissions: { create: [{ permission: 'MANAGE_USERS' }] } } });
    ids.admin = adminRole.id;
    ids.hr = hrRole.id;
    admin = await createUser('eleni@example.com', { roleIds: [adminRole.id] });
    await prisma.orgKeyGrant.create({ data: { userId: admin.id, encryptedOrgPrivateKey: `rsa.${b64()}`, grantedById: admin.id } });
    hr = await createUser('maria@example.com', { roleIds: [hrRole.id] });
    dev = await createUser('vasilis@example.com');
    newbie = await createUser('niki@example.com', { invited: true });
    adminAgent = await signIn(admin.email, admin.authVerifier);
  });

  afterAll(async () => {
    await app.close();
  });

  describe('defining roles', () => {
    it('creates a role with permissions', async () => {
      const res = await adminAgent.post('/roles').send({ name: ' Developers ', description: 'Dev team', permissions: ['SHARE_CREDENTIALS'] }).expect(201);
      expect(res.body).toMatchObject({ name: 'Developers', permissions: ['SHARE_CREDENTIALS'], userCount: 0, vaultGrants: [] });
      ids.devs = res.body.id;
    });

    it('rejects a duplicate name and an unknown permission', async () => {
      await adminAgent.post('/roles').send({ name: 'Developers', permissions: [] }).expect(409);
      await adminAgent.post('/roles').send({ name: 'X', permissions: ['SUPERUSER'] }).expect(400);
    });

    it('lists roles and the permission catalogue to any signed-in user', async () => {
      const devAgent = await signIn(dev.email, dev.authVerifier);
      const roles = await devAgent.get('/roles').expect(200);
      expect(roles.body.map((r: { name: string }) => r.name)).toEqual(['Admin', 'Developers', 'HR']);
      const permissions = await devAgent.get('/roles/permissions').expect(200);
      expect(permissions.body).toHaveLength(7);
      await http().get('/roles').expect(401);
    });

    it('needs MANAGE_ROLES to create roles', async () => {
      const hrAgent = await signIn(hr.email, hr.authVerifier);
      await hrAgent.post('/roles').send({ name: 'Mine', permissions: [] }).expect(403);
    });
  });

  describe('no privilege escalation', () => {
    it('an HR user cannot give anyone, including themselves, a role with permissions they lack', async () => {
      const hrAgent = await signIn(hr.email, hr.authVerifier);
      const res = await hrAgent.post(`/users/${hr.id}/roles`).send({ roleId: ids.admin }).expect(403);
      expect(res.body.message).toContain('ORG_ADMIN');
      await hrAgent.post(`/users/${dev.id}/roles`).send({ roleId: ids.devs }).expect(403); // SHARE_CREDENTIALS
    });

    it('nor invite someone straight into such a role', async () => {
      const hrAgent = await signIn(hr.email, hr.authVerifier);
      await hrAgent.post('/invitations').send({ email: 'boss@example.com', name: 'Boss', roleIds: [ids.admin] }).expect(403);
    });

    it('nor take a role away from the real admin', async () => {
      const hrAgent = await signIn(hr.email, hr.authVerifier);
      await hrAgent.delete(`/users/${admin.id}/roles/${ids.admin}`).expect(403);
    });
  });

  describe('assigning roles with their keys', () => {
    let devVault: Awaited<ReturnType<typeof vaultWithCredentials>>;

    beforeAll(async () => {
      devVault = await vaultWithCredentials('Dev servers', admin.id, 2);
      await prisma.vaultRoleGrant.create({ data: { vaultId: devVault.vault.id, roleId: ids.devs, accessLevel: 'EDITOR', grantedById: admin.id } });
    });

    it('requires exactly one vault key per vault of the role', async () => {
      await adminAgent.post(`/users/${dev.id}/roles`).send({ roleId: ids.devs }).expect(400);
      await adminAgent
        .post(`/users/${dev.id}/roles`)
        .send({ roleId: ids.devs, vaultKeys: [{ vaultId: devVault.vault.id, encryptedVaultKey: 'a' }, { vaultId: devVault.vault.id, encryptedVaultKey: 'b' }] })
        .expect(400);
    });

    it('saves the role and the locked vault key together', async () => {
      const res = await adminAgent
        .post(`/users/${dev.id}/roles`)
        .send({ roleId: ids.devs, vaultKeys: [{ vaultId: devVault.vault.id, encryptedVaultKey: `rsa.${b64()}` }] })
        .expect(201);
      expect(res.body.keysPending).toBe(false);
      const key = await prisma.vaultKey.findFirstOrThrow({ where: { userId: dev.id, vaultId: devVault.vault.id } });
      expect(key).toMatchObject({ viaRoleId: ids.devs, accessLevel: 'EDITOR', grantedById: admin.id });
      await adminAgent.post(`/users/${dev.id}/roles`).send({ roleId: ids.devs, vaultKeys: [] }).expect(409);
    });

    it('leaves the keys pending for a user who has not registered yet', async () => {
      const res = await adminAgent.post(`/users/${newbie.id}/roles`).send({ roleId: ids.devs }).expect(201);
      expect(res.body.keysPending).toBe(true);
      expect(await prisma.vaultKey.count({ where: { userId: newbie.id } })).toBe(0);
    });

    it('needs the organization key when the role brings ORG_ADMIN', async () => {
      await adminAgent.post(`/users/${dev.id}/roles`).send({ roleId: ids.admin }).expect(400);
      await adminAgent.post(`/users/${dev.id}/roles`).send({ roleId: ids.admin, encryptedOrgPrivateKey: `rsa.${b64()}` }).expect(201);
      expect(await prisma.orgKeyGrant.findUnique({ where: { userId: dev.id } })).not.toBeNull();
      const me = await (await signIn(dev.email, dev.authVerifier)).get('/auth/me').expect(200);
      expect(me.body.permissions).toContain('ORG_ADMIN');
    });

    it('lists users with their roles and public keys', async () => {
      const res = await adminAgent.get('/users').expect(200);
      const vasilis = res.body.find((u: { email: string }) => u.email === dev.email);
      expect(vasilis.roles.map((r: { name: string }) => r.name).sort()).toEqual(['Admin', 'Developers']);
      expect(vasilis.publicKey).toMatch(/^pk\./);
    });
  });

  describe('removing roles and the rotation list', () => {
    it('while still an org admin, losing a group role costs nothing', async () => {
      const res = await adminAgent.delete(`/users/${dev.id}/roles/${ids.devs}`).expect(200);
      expect(res.body.rotationTasks).toBe(0); // ORG_ADMIN still opens every vault
      expect(await prisma.vaultKey.count({ where: { userId: dev.id, viaRoleId: ids.devs } })).toBe(0);
    });

    it('losing ORG_ADMIN deletes the org key and lists every credential the user can no longer reach', async () => {
      const personal = await vaultWithCredentials('Eleni personal', admin.id, 1, 'PERSONAL');
      const marketing = await vaultWithCredentials('Marketing', admin.id, 1);
      // Still shared with Vasilis directly: he keeps it, so it is not listed.
      await prisma.credentialShare.create({
        data: { credentialId: marketing.credentials[0]!.id, userId: dev.id, encryptedItemKey: `rsa.${b64()}`, accessLevel: 'VIEWER', grantedById: admin.id },
      });

      const res = await adminAgent.delete(`/users/${dev.id}/roles/${ids.admin}`).expect(200);
      expect(res.body.rotationTasks).toBe(3); // 2 dev servers + Eleni's personal one
      expect(await prisma.orgKeyGrant.findUnique({ where: { userId: dev.id } })).toBeNull();
      const tasks = await prisma.rotationTask.findMany({ where: { exposedUserId: dev.id } });
      expect(tasks.map((t) => t.credentialId)).toContain(personal.credentials[0]!.id);
      expect(tasks.every((t) => t.triggeredById === admin.id && t.resolvedAt === null)).toBe(true);
    });

    it('losing a group role lists that group\'s credentials, once', async () => {
      const devVault = await prisma.vault.findFirstOrThrow({ where: { name: 'Dev servers' } });
      await adminAgent
        .post(`/users/${dev.id}/roles`)
        .send({ roleId: ids.devs, vaultKeys: [{ vaultId: devVault.id, encryptedVaultKey: `rsa.${b64()}` }] })
        .expect(201);
      const res = await adminAgent.delete(`/users/${dev.id}/roles/${ids.devs}`).expect(200);
      expect(res.body.rotationTasks).toBe(0); // already on the list from the previous step, still open
      expect(await prisma.rotationTask.count({ where: { exposedUserId: dev.id } })).toBe(3);
    });

    it('the last active admin cannot remove their own Admin role', async () => {
      const res = await adminAgent.delete(`/users/${admin.id}/roles/${ids.admin}`).expect(409);
      expect(res.body.message).toBe('The organization needs at least one active admin');
      expect(await prisma.orgKeyGrant.findUnique({ where: { userId: admin.id } })).not.toBeNull(); // rolled back
    });
  });

  describe('editing and deleting roles', () => {
    it('renames a role and replaces its permissions', async () => {
      const res = await adminAgent.patch(`/roles/${ids.devs}`).send({ name: 'Engineering', permissions: ['SHARE_CREDENTIALS', 'ROTATE_CREDENTIALS'] }).expect(200);
      expect(res.body).toMatchObject({ name: 'Engineering', permissions: expect.arrayContaining(['SHARE_CREDENTIALS', 'ROTATE_CREDENTIALS']) });
    });

    it('will not move ORG_ADMIN in or out of a role that has users', async () => {
      await adminAgent.patch(`/roles/${ids.admin}`).send({ permissions: ['MANAGE_USERS'] }).expect(409);
      await adminAgent.patch(`/roles/${ids.hr}`).send({ permissions: ['MANAGE_USERS', 'ORG_ADMIN'] }).expect(409);
    });

    it('deletes a role only when nobody has it', async () => {
      await adminAgent.delete(`/roles/${ids.hr}`).expect(409);
      await adminAgent.delete(`/users/${hr.id}/roles/${ids.hr}`).expect(200);
      await adminAgent.delete(`/roles/${ids.hr}`).expect(204);
      await adminAgent.delete(`/roles/${ids.hr}`).expect(404);
      await adminAgent.delete('/roles/not-a-uuid').expect(400);
    });

    it('records role changes in the audit log', async () => {
      const actions = (await prisma.auditLog.findMany({ select: { action: true } })).map((a) => a.action);
      expect(actions).toEqual(expect.arrayContaining(['ROLE_CREATED', 'ROLE_UPDATED', 'ROLE_DELETED', 'ROLE_ASSIGNED', 'ROLE_REMOVED']));
    });
  });
});
