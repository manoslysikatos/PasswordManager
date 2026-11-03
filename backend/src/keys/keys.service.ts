import { BadRequestException, Injectable } from '@nestjs/common';
import { AuditService } from '../audit/audit.service.js';
import type { AuthUser } from '../common/auth.decorators.js';
import { hasOrgKey, manageableVaults } from '../common/vault-access.js';
import type { Prisma } from '../generated/prisma/client.js';
import { PrismaService } from '../prisma/prisma.service.js';
import type { FulfilKeysDto } from './dto.js';

const vaultKeyId = (vaultId: string, userId: string, roleId: string) => `${vaultId}|${userId}|${roleId}`;

// The policy (who has which role, which role opens which vault) changes at once; the keys follow
// whenever a browser that holds them comes by. "Pending" = the policy says a user should have a key,
// but nobody has locked it for them yet. Typical causes:
// - the user registered after getting the role (they had no public key before)
// - the role was given by someone who cannot open the vault (e.g. HR with MANAGE_USERS)
// - a vault was just connected to a role that already has members
@Injectable()
export class KeysService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  /** The pending keys this user's browser can lock: for vaults they manage, and the org key if they hold it. */
  async pending(actor: AuthUser, only?: { vaultId: string; roleId: string }, db: Prisma.TransactionClient = this.prisma) {
    const grants = await db.vaultRoleGrant.findMany({
      where: { ...only, vault: await manageableVaults(db, actor.id) },
      include: {
        vault: { select: { name: true } },
        role: {
          select: {
            name: true,
            users: {
              where: { user: { status: 'ACTIVE', publicKey: { not: null } } },
              select: { user: { select: { id: true, name: true, email: true, publicKey: true } } },
            },
          },
        },
      },
    });
    const existing = await db.vaultKey.findMany({
      where: { vaultId: { in: grants.map((g) => g.vaultId) }, viaRoleId: { not: null } },
      select: { vaultId: true, userId: true, viaRoleId: true },
    });
    const have = new Set(existing.map((k) => vaultKeyId(k.vaultId, k.userId, k.viaRoleId!)));

    const vaultKeys = grants.flatMap((grant) =>
      grant.role.users
        .filter(({ user }) => !have.has(vaultKeyId(grant.vaultId, user.id, grant.roleId)))
        .map(({ user }) => ({
          vaultId: grant.vaultId,
          vaultName: grant.vault.name,
          roleId: grant.roleId,
          roleName: grant.role.name,
          accessLevel: grant.accessLevel,
          userId: user.id,
          userName: user.name,
          email: user.email,
          publicKey: user.publicKey!,
        })),
    );

    const orgKeys =
      !only && (await hasOrgKey(db, actor.id))
        ? await db.user.findMany({
            where: {
              status: 'ACTIVE',
              publicKey: { not: null },
              orgKeyGrant: { is: null },
              roles: { some: { role: { permissions: { some: { permission: 'ORG_ADMIN' } } } } },
            },
            select: { id: true, name: true, email: true, publicKey: true },
          })
        : [];

    return { vaultKeys, orgKeys: orgKeys.map(({ id, ...user }) => ({ userId: id, ...user, publicKey: user.publicKey! })) };
  }

  /** Stores keys locked in the browser; each one must answer a request this user can see right now. */
  async fulfil(dto: FulfilKeysDto, actor: AuthUser) {
    const vaultKeys = dto.vaultKeys ?? [];
    const orgKeys = dto.orgKeys ?? [];

    await this.prisma.$transaction(async (tx) => {
      const pending = await this.pending(actor, undefined, tx);
      const vaultRequests = new Map(pending.vaultKeys.map((r) => [vaultKeyId(r.vaultId, r.userId, r.roleId), r]));
      const orgRequests = new Set(pending.orgKeys.map((r) => r.userId));

      const sent = new Set<string>();
      for (const key of vaultKeys) {
        const id = vaultKeyId(key.vaultId, key.userId, key.roleId);
        if (!vaultRequests.has(id) || sent.has(id)) throw new BadRequestException(`Not a pending vault key: ${id}`);
        sent.add(id);
      }
      if (orgKeys.some((key) => !orgRequests.has(key.userId)) || new Set(orgKeys.map((k) => k.userId)).size !== orgKeys.length) {
        throw new BadRequestException('Not a pending organization key');
      }

      await tx.vaultKey.createMany({
        data: vaultKeys.map((key) => ({
          vaultId: key.vaultId,
          userId: key.userId,
          viaRoleId: key.roleId,
          encryptedVaultKey: key.encryptedVaultKey,
          accessLevel: vaultRequests.get(vaultKeyId(key.vaultId, key.userId, key.roleId))!.accessLevel,
          grantedById: actor.id,
        })),
      });
      await tx.orgKeyGrant.createMany({
        data: orgKeys.map((key) => ({ userId: key.userId, encryptedOrgPrivateKey: key.encryptedOrgPrivateKey, grantedById: actor.id })),
      });
    });

    if (vaultKeys.length + orgKeys.length > 0) {
      await this.audit.log('KEYS_GRANTED', { userId: actor.id, metadata: { vaultKeys: vaultKeys.length, orgKeys: orgKeys.length } });
    }
    return { vaultKeys: vaultKeys.length, orgKeys: orgKeys.length };
  }
}
