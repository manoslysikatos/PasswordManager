import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { AuditService } from '../audit/audit.service.js';
import type { AuthUser } from '../common/auth.decorators.js';
import { assertHoldsAll } from '../common/permissions.js';
import { Permission, Prisma } from '../generated/prisma/client.js';
import { PrismaService } from '../prisma/prisma.service.js';
import type { CreateRoleDto, UpdateRoleDto } from './dto.js';

const ROLE_VIEW = {
  id: true,
  name: true,
  description: true,
  permissions: { select: { permission: true } },
  vaultGrants: { select: { vaultId: true, accessLevel: true } },
  _count: { select: { users: true } },
} satisfies Prisma.RoleSelect;

type RoleRow = Prisma.RoleGetPayload<{ select: typeof ROLE_VIEW }>;

function toView(role: RoleRow) {
  return {
    id: role.id,
    name: role.name,
    description: role.description,
    permissions: role.permissions.map((p) => p.permission),
    vaultGrants: role.vaultGrants,
    userCount: role._count.users,
  };
}

// Roles are definitions: a name, a set of permissions, and (later) the vaults they open.
// Who has which role is managed in UsersService.
@Injectable()
export class RolesService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  allPermissions(): Permission[] {
    return Object.values(Permission);
  }

  async list() {
    const roles = await this.prisma.role.findMany({ select: ROLE_VIEW, orderBy: { name: 'asc' } });
    return roles.map(toView);
  }

  async create(dto: CreateRoleDto, actor: AuthUser) {
    assertHoldsAll(actor, dto.permissions);
    const role = await this.uniqueName(() =>
      this.prisma.role.create({
        data: {
          name: dto.name,
          description: dto.description,
          permissions: { create: dto.permissions.map((permission) => ({ permission })) },
        },
        select: ROLE_VIEW,
      }),
    );
    await this.audit.log('ROLE_CREATED', {
      userId: actor.id,
      targetType: 'role',
      targetId: role.id,
      metadata: { permissions: dto.permissions.join(',') },
    });
    return toView(role);
  }

  async update(id: string, dto: UpdateRoleDto, actor: AuthUser) {
    const role = await this.find(id);
    const current = role.permissions.map((p) => p.permission);
    if (dto.permissions) {
      // Editing a role changes what its holders can do, so both the old and the new set count.
      assertHoldsAll(actor, [...current, ...dto.permissions]);
      // ORG_ADMIN comes with the organization key. Giving or taking it from people goes through
      // assigning or removing the role, where the browser locks the key or the rotation list is made.
      if (current.includes('ORG_ADMIN') !== dto.permissions.includes('ORG_ADMIN') && role._count.users > 0) {
        throw new ConflictException('ORG_ADMIN can only be added to or removed from a role without users');
      }
    } else {
      assertHoldsAll(actor, current);
    }

    const updated = await this.uniqueName(() =>
      this.prisma.$transaction(async (tx) => {
        if (dto.permissions) {
          await tx.rolePermission.deleteMany({ where: { roleId: id } });
          await tx.rolePermission.createMany({ data: dto.permissions.map((permission) => ({ roleId: id, permission })) });
        }
        return tx.role.update({ where: { id }, data: { name: dto.name, description: dto.description }, select: ROLE_VIEW });
      }),
    );
    await this.audit.log('ROLE_UPDATED', {
      userId: actor.id,
      targetType: 'role',
      targetId: id,
      metadata: dto.permissions ? { permissions: dto.permissions.join(',') } : undefined,
    });
    return toView(updated);
  }

  async remove(id: string, actor: AuthUser): Promise<void> {
    const role = await this.find(id);
    assertHoldsAll(actor, role.permissions.map((p) => p.permission));
    // Deleting a role in use would silently revoke access, without the rotation list (decision 0009).
    if (role._count.users > 0) {
      throw new ConflictException('Remove the role from its users first');
    }
    await this.prisma.role.delete({ where: { id } });
    await this.audit.log('ROLE_DELETED', { userId: actor.id, targetType: 'role', targetId: id, metadata: { name: role.name } });
  }

  private async find(id: string) {
    const role = await this.prisma.role.findUnique({ where: { id }, select: ROLE_VIEW });
    if (!role) throw new NotFoundException('Role not found');
    return role;
  }

  private async uniqueName<T>(write: () => Promise<T>): Promise<T> {
    try {
      return await write();
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
        throw new ConflictException('A role with this name already exists');
      }
      throw error;
    }
  }
}
