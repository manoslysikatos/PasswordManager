import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { AuditService } from '../audit/audit.service.js';
import type { AuthUser } from '../common/auth.decorators.js';
import { assertHoldsAll } from '../common/permissions.js';
import type { Prisma } from '../generated/prisma/client.js';
import { PrismaService } from '../prisma/prisma.service.js';
import type { AssignRoleDto } from './dto.js';
import { flagForRotation } from './rotation.js';

const sameSet = (a: string[], b: string[]) => a.length === b.length && a.every((x) => b.includes(x));

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
   * Gives a role, together with the keys it needs (decision 0012: access is usable immediately).
   * A user who has not registered yet has no public key, so nothing can be locked for them: the
   * role is saved and the keys follow later (pending assignment).
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

      const pending = user.publicKey === null;
      const needsOrgKey = !pending && permissions.includes('ORG_ADMIN') && !user.orgKeyGrant;
      if (needsOrgKey !== (dto.encryptedOrgPrivateKey !== undefined)) {
        throw new BadRequestException(
          needsOrgKey ? 'This role needs the organization key locked for the user' : 'No organization key is expected',
        );
      }
      const neededVaults = pending ? [] : role.vaultGrants.map((g) => g.vaultId);
      const sentVaults = (dto.vaultKeys ?? []).map((k) => k.vaultId);
      if (!sameSet(neededVaults, sentVaults)) {
        throw new BadRequestException('Send exactly one vault key for each vault of this role');
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
      const keysPending = pending && (permissions.includes('ORG_ADMIN') || role.vaultGrants.length > 0);
      return { userId, roleId: role.id, keysPending };
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

        const stillOrgAdmin =
          (await tx.rolePermission.count({ where: { permission: 'ORG_ADMIN', role: { users: { some: { userId } } } } })) > 0;
        // A user who can still open everything has lost nothing.
        if (stillOrgAdmin) return 0;

        // Credentials in vaults the user can no longer open (through another role, or directly).
        const unreachable: Prisma.CredentialWhereInput = { vault: { keys: { none: { userId } } } };
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
