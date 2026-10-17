import { type CanActivate, type ExecutionContext, ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { type AuthRequest, IS_PUBLIC, REQUIRED_PERMISSIONS } from '../common/auth.decorators.js';
import type { Permission } from '../generated/prisma/client.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { ACCESS_COOKIE } from './cookies.js';

// Registered globally: every endpoint needs a valid session unless marked @Public().
// The user and their permissions are loaded from the database on each request, so a deactivated
// user or a removed role takes effect immediately, not when the token expires.
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly jwt: JwtService,
    private readonly prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const targets = [context.getHandler(), context.getClass()];
    if (this.reflector.getAllAndOverride<boolean>(IS_PUBLIC, targets)) return true;

    const req = context.switchToHttp().getRequest<AuthRequest>();
    const token: unknown = req.cookies?.[ACCESS_COOKIE];
    if (typeof token !== 'string') throw new UnauthorizedException();

    let userId: string;
    try {
      userId = (await this.jwt.verifyAsync<{ sub: string }>(token)).sub;
    } catch {
      throw new UnauthorizedException();
    }

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { roles: { include: { role: { include: { permissions: true } } } } },
    });
    if (!user || user.status !== 'ACTIVE') throw new UnauthorizedException();

    const permissions = [...new Set(user.roles.flatMap((ur) => ur.role.permissions.map((p) => p.permission)))];
    req.user = { id: user.id, email: user.email, name: user.name, permissions };

    const required = this.reflector.getAllAndOverride<Permission[] | undefined>(REQUIRED_PERMISSIONS, targets) ?? [];
    if (required.some((permission) => !permissions.includes(permission))) {
      throw new ForbiddenException('Missing permission');
    }
    return true;
  }
}
