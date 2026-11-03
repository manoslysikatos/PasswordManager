import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { AuditService } from '../audit/audit.service.js';
import type { AuthUser } from '../common/auth.decorators.js';
import { flagForRotation, isOrgAdmin, unreachableBy } from '../common/rotation.js';
import { findManageableVault } from '../common/vault-access.js';
import { type AccessLevel, Prisma } from '../generated/prisma/client.js';
import { KeysService } from '../keys/keys.service.js';
import { PrismaService } from '../prisma/prisma.service.js';
import type { CreateVaultDto, GrantRoleDto, RenameVaultDto, RoleAccessDto } from './dto.js';

const RANK: Record<AccessLevel, number> = { OWNER: 3, EDITOR: 2, VIEWER: 1 };

// A group is a SHARED vault. The policy part ("role X may use vault Y") lives in vault_role_grants;
// the cryptographic part (the vault key locked for each member) in vault_keys, via KeysService.
@Injectable()
export class VaultsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly keys: KeysService,
  ) {}

  /** The vaults this user can open with their own keys; with several ways in, the strongest one counts. */
  async listMine(actor: AuthUser) {
    const keys = await this.prisma.vaultKey.findMany({
      where: { userId: actor.id },
      include: { vault: { select: { name: true, type: true, _count: { select: { credentials: true } } } } },
    });
    const best = new Map<string, (typeof keys)[number]>();
    for (const key of keys) {
      const current = best.get(key.vaultId);
      if (!current || RANK[key.accessLevel] > RANK[current.accessLevel]) best.set(key.vaultId, key);
    }
    return [...best.values()]
      .map((key) => ({
        id: key.vaultId,
        name: key.vault.name,
        type: key.vault.type,
        accessLevel: key.accessLevel,
        encryptedVaultKey: key.encryptedVaultKey,
        credentialCount: key.vault._count.credentials,
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  /** Every vault, for org admins: their browser opens each one with the org key (orgEncryptedVaultKey). */
  async listAll() {
    const vaults = await this.prisma.vault.findMany({
      select: {
        id: true,
        name: true,
        type: true,
        orgEncryptedVaultKey: true,
        owner: { select: { id: true, name: true } },
        roleGrants: { select: { accessLevel: true, role: { select: { id: true, name: true } } } },
        _count: { select: { credentials: true } },
      },
      orderBy: [{ type: 'asc' }, { name: 'asc' }],
    });
    return vaults.map(({ roleGrants, _count, ...vault }) => ({
      ...vault,
      roles: roleGrants.map((g) => ({ ...g.role, accessLevel: g.accessLevel })),
      credentialCount: _count.credentials,
    }));
  }

  async create(dto: CreateVaultDto, actor: AuthUser) {
    const vault = await this.prisma.vault.create({
      data: {
        name: dto.name,
        type: 'SHARED',
        ownerId: actor.id,
        orgEncryptedVaultKey: dto.orgEncryptedVaultKey,
        keys: { create: { userId: actor.id, encryptedVaultKey: dto.encryptedVaultKey, accessLevel: 'OWNER', grantedById: actor.id } },
      },
      select: { id: true, name: true, type: true },
    });
    await this.audit.log('VAULT_CREATED', { userId: actor.id, targetType: 'vault', targetId: vault.id });
    return vault;
  }

  async rename(id: string, dto: RenameVaultDto, actor: AuthUser) {
    await findManageableVault(this.prisma, actor.id, id);
    const vault = await this.prisma.vault.update({ where: { id }, data: { name: dto.name }, select: { id: true, name: true, type: true } });
    await this.audit.log('VAULT_UPDATED', { userId: actor.id, targetType: 'vault', targetId: id, metadata: { name: dto.name } });
    return vault;
  }

  /**
   * Connects a group to a role. Returns the keys to lock now, one per current member: the caller's
   * browser can do it straight away (POST /keys/pending), so access is usable immediately (decision 0012).
   */
  async grantRole(id: string, dto: GrantRoleDto, actor: AuthUser) {
    const vault = await findManageableVault(this.prisma, actor.id, id);
    if (vault.type === 'PERSONAL') throw new BadRequestException('A personal vault cannot be shared with a role');
    if ((await this.prisma.role.count({ where: { id: dto.roleId } })) === 0) throw new BadRequestException('Unknown role');

    try {
      await this.prisma.vaultRoleGrant.create({ data: { vaultId: id, roleId: dto.roleId, accessLevel: dto.accessLevel, grantedById: actor.id } });
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
        throw new ConflictException('This role already has access to the vault');
      }
      throw error;
    }
    await this.audit.log('VAULT_SHARED', {
      userId: actor.id,
      targetType: 'vault',
      targetId: id,
      metadata: { roleId: dto.roleId, accessLevel: dto.accessLevel },
    });
    const { vaultKeys } = await this.keys.pending(actor, { vaultId: id, roleId: dto.roleId });
    return { vaultId: id, roleId: dto.roleId, accessLevel: dto.accessLevel, keyRequests: vaultKeys };
  }

  /** Viewer ↔ editor. The keys stay the same; only what the server lets the members do changes. */
  async changeRoleAccess(id: string, roleId: string, dto: RoleAccessDto, actor: AuthUser) {
    await findManageableVault(this.prisma, actor.id, id);
    await this.prisma.$transaction(async (tx) => {
      const updated = await tx.vaultRoleGrant.updateMany({ where: { vaultId: id, roleId }, data: { accessLevel: dto.accessLevel } });
      if (updated.count === 0) throw new NotFoundException('This role has no access to the vault');
      await tx.vaultKey.updateMany({ where: { vaultId: id, viaRoleId: roleId }, data: { accessLevel: dto.accessLevel } });
    });
    await this.audit.log('VAULT_UPDATED', { userId: actor.id, targetType: 'vault', targetId: id, metadata: { roleId, accessLevel: dto.accessLevel } });
    return { vaultId: id, roleId, accessLevel: dto.accessLevel };
  }

  /**
   * Disconnects a group from a role: the members' keys for it are deleted, and whoever can no longer
   * open the vault leaves its credentials on the rotation list (decision 0009).
   */
  async revokeRole(id: string, roleId: string, actor: AuthUser) {
    await findManageableVault(this.prisma, actor.id, id);
    const rotationTasks = await this.prisma.$transaction(async (tx) => {
      const removed = await tx.vaultRoleGrant.deleteMany({ where: { vaultId: id, roleId } });
      if (removed.count === 0) throw new NotFoundException('This role has no access to the vault');
      const members = await tx.vaultKey.findMany({ where: { vaultId: id, viaRoleId: roleId }, select: { userId: true } });
      await tx.vaultKey.deleteMany({ where: { vaultId: id, viaRoleId: roleId } });

      let flagged = 0;
      for (const { userId } of members) {
        if (await isOrgAdmin(tx, userId)) continue;
        flagged += await flagForRotation(tx, { AND: [{ vaultId: id }, unreachableBy(userId)] }, userId, actor.id);
      }
      return flagged;
    });
    await this.audit.log('VAULT_ACCESS_REVOKED', { userId: actor.id, targetType: 'vault', targetId: id, metadata: { roleId, rotationTasks } });
    return { rotationTasks };
  }
}
