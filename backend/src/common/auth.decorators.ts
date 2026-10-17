import { createParamDecorator, type ExecutionContext, SetMetadata } from '@nestjs/common';
import type { Request } from 'express';
import type { Permission } from '../generated/prisma/client.js';

/** The signed-in user, as loaded by AuthGuard on every request. */
export interface AuthUser {
  id: string;
  email: string;
  name: string;
  permissions: Permission[];
}

export type AuthRequest = Request & { user?: AuthUser };

export const IS_PUBLIC = 'isPublic';
/** Opens an endpoint to anyone. Every other endpoint requires a valid session. */
export const Public = () => SetMetadata(IS_PUBLIC, true);

export const REQUIRED_PERMISSIONS = 'requiredPermissions';
/** The signed-in user must hold all of these permissions, through any of their roles. */
export const RequirePermission = (...permissions: Permission[]) => SetMetadata(REQUIRED_PERMISSIONS, permissions);

export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): AuthUser | undefined => ctx.switchToHttp().getRequest<AuthRequest>().user,
);

/** IP and user agent, stored with audit log entries. */
export function requestMeta(req: Request): { ip: string | null; userAgent: string | null } {
  return { ip: req.ip ?? null, userAgent: req.get('user-agent') ?? null };
}
