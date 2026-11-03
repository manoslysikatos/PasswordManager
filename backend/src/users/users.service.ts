import { BadRequestException, ConflictException, ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { AuditService } from '../audit/audit.service.js';
import type { AuthUser } from '../common/auth.decorators.js';
import { assertHoldsAll } from '../common/permissions.js';
import { flagForRotation, isOrgAdmin, unreachableBy } from '../common/rotation.js';
import { manageableVaults } from '../common/vault-access.js';
import type { Prisma } from '../generated/prisma/client.js';
import { PrismaService } from '../prisma/prisma.service.js';
import type { AssignRoleDto } from './dto.js';

@Injectable()
export class UsersService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  /** Includes each user's public key: the admin's browser needs it to lock keys for that user. */
  async list() {
    const users = await this.prisma.user.findMany({
      select: {
        id: true,
        email: true,
        name: true,
        status: true,
        publicKey: true,
        roles: { select: { role: { select: { id: true, name: true } } } },
      },
      orderBy: { email: 'asc' },
    });
    return users.map(({ roles, ...user }) => ({ ...user, roles: roles.map((r) => r.role) }));
  }

  /**
   * Gives a role, together with whatever keys the caller's browser can lock right away (decision 0012).
   * Missing keys wait in GET /keys/pending: the user has not registered yet (no public key), or the
   * caller cannot open the role's vaults (e.g. HR with MANAGE_USERS only).
   */
  async assignRole(userId: string, dto: AssignRoleDto, actor: AuthUser) {
    const result = await this.prisma.$transaction(async (tx) => {
      const user = await tx.user.findUnique({ where: { id: userId }, include: { roles: true, orgKeyGrant: true } });
      if (!user) throw new NotFoundException('User not found');
      if (user.status === 'DEACTIVATED') throw new ConflictException('The user is deactivated');

      const role = await tx.role.findUnique({ where: { id: dto.roleId }, include: { permissions: true, vaultGrants: true } });
      if (!role) throw new BadRequestException('Unknown role');
      const permissions = role.permissions.map((p) => p.permission);
      assertHoldsAll(actor, permissions);
      if (user.roles.some((r) => r.roleId === role.id)) throw new ConflictException('The user already has this role');

      // Keys can only be locked for a user who has a public key, i.e. has registered.
      const registered = user.publicKey !== null;
      const needsOrgKey = registered && permissions.includes('ORG_ADMIN') && !user.orgKeyGrant;
      const neededVaults = registered ? role.vaultGrants.map((g) => g.vaultId) : [];
      const sentVaults = (dto.vaultKeys ?? []).map((k) => k.vaultId);

      if (dto.encryptedOrgPrivateKey !== undefined && !needsOrgKey) throw new BadRequestException('No organization key is expected');
      if (sentVaults.some((vaultId) => !neededVaults.includes(vaultId))) {
        throw new BadRequestException('A vault key was sent for a vault this role does not open');
      }
      // A key can only come from a browser that can open the vault; anything else would be garbage.
      if (sentVaults.length > 0) {
        const manageable = await tx.vault.count({ where: { AND: [{ id: { in: sentVaults } }, await manageableVaults(tx, actor.id)] } });
        if (manageable !== sentVaults.length) throw new ForbiddenException('You can only lock keys of vaults you manage');
      }

      await tx.userRole.create({ data: { userId, roleId: role.id } });
      if (dto.encryptedOrgPrivateKey !== undefined) {
        await tx.orgKeyGrant.create({ data: { userId, encryptedOrgPrivateKey: dto.encryptedOrgPrivateKey, grantedById: actor.id } });
      }
      if (dto.vaultKeys?.length) {
        const levels = new Map(role.vaultGrants.map((g) => [g.vaultId, g.accessLevel]));
        await tx.vaultKey.createMany({
          data: dto.vaultKeys.map((k) => ({
            vaultId: k.vaultId,
            userId,
            viaRoleId: role.id,
            encryptedVaultKey: k.encryptedVaultKey,
            accessLevel: levels.get(k.vaultId)!,
            grantedById: actor.id,
          })),
        });
      }
      // Whatever was not sent now waits in GET /keys/pending for someone who can lock it.
      const orgKeyMissing = permissions.includes('ORG_ADMIN') && !user.orgKeyGrant && dto.encryptedOrgPrivateKey === undefined;
      return { userId, roleId: role.id, keysPending: orgKeyMissing || sentVaults.length < role.vaultGrants.length };
    });

    await this.audit.log('ROLE_ASSIGNED', { userId: actor.id, targetType: 'user', targetId: userId, metadata: { roleId: dto.roleId } });
    return result;
  }

  /**
   * Takes a role away: its vault keys are deleted, and, if that was the user's last way into a vault,
   * its credentials go on the rotation list (decision 0009). Losing ORG_ADMIN also deletes the user's
   * copy of the organization key, and every credential they could reach only through it is listed.
   */
  async removeRole(userId: string, roleId: string, actor: AuthUser) {
    const rotationTasks = await this.prisma.$transaction(
      async (tx) => {
        const assignment = await tx.userRole.findUnique({
          where: { userId_roleId: { userId, roleId } },
          include: { role: { include: { permissions: true } } },
        });
        if (!assignment) throw new NotFoundException('The user does not have this role');
        const permissions = assignment.role.permissions.map((p) => p.permission);
        assertHoldsAll(actor, permissions);

        await tx.userRole.delete({ where: { userId_roleId: { userId, roleId } } });
        const lostVaults = (await tx.vaultKey.findMany({ where: { userId, viaRoleId: roleId }, select: { vaultId: true } })).map(
          (k) => k.vaultId,
        );
        await tx.vaultKey.deleteMany({ where: { userId, viaRoleId: roleId } });

        // A user who can still open everything has lost nothing.
        if (await isOrgAdmin(tx, userId)) return 0;

        const unreachable = unreachableBy(userId);
        if (permissions.includes('ORG_ADMIN')) {
          if ((await this.countActiveOrgAdmins(tx)) === 0) {
            throw new ConflictException('The organization needs at least one active admin');
          }
          await tx.orgKeyGrant.deleteMany({ where: { userId } });
          return flagForRotation(tx, unreachable, userId, actor.id);
        }
        if (lostVaults.length === 0) return 0;
        return flagForRotation(tx, { AND: [{ vaultId: { in: lostVaults } }, unreachable] }, userId, actor.id);
      },
      // The "last admin" check must see a consistent picture, even if two admins remove each other at once.
      { isolationLevel: 'Serializable' },
    );

    await this.audit.log('ROLE_REMOVED', {
      userId: actor.id,
      targetType: 'user',
      targetId: userId,
      metadata: { roleId, rotationTasks },
    });
    return { rotationTasks };
  }

  private countActiveOrgAdmins(tx: Prisma.TransactionClient) {
    return tx.user.count({
      where: { status: 'ACTIVE', roles: { some: { role: { permissions: { some: { permission: 'ORG_ADMIN' } } } } } },
    });
  }
}
