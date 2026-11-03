import { ForbiddenException } from '@nestjs/common';
import type { Permission } from '../generated/prisma/client.js';
import type { AuthUser } from './auth.decorators.js';

/**
 * No privilege escalation: you can only hand out, or take away, permissions you hold yourself.
 * Otherwise someone with MANAGE_USERS could give themselves the Admin role, or strip it from the real admin.
 */
export function assertHoldsAll(actor: AuthUser, permissions: readonly Permission[]): void {
  const missing = [...new Set(permissions)].filter((permission) => !actor.permissions.includes(permission));
  if (missing.length > 0) {
    throw new ForbiddenException(`You cannot grant or remove permissions you do not hold: ${missing.join(', ')}`);
  }
}
