import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import type { Response } from 'express';
import { AuditService } from '../audit/audit.service.js';
import type { AuthUser } from '../common/auth.decorators.js';
import {
  DEFAULT_KDF_PARAMS,
  dummyVerifierHash,
  fakeKdfSalt,
  randomToken,
  sha256,
  verifyVerifier,
} from '../common/crypto.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { clearAuthCookies, REFRESH_TTL_MS, setAuthCookies } from './cookies.js';
import type { LoginDto } from './dto.js';

type Meta = { ip: string | null; userAgent: string | null };

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly audit: AuditService,
    private readonly config: ConfigService,
  ) {}

  /** Step 1 of login: the browser needs the salt and Argon2 settings to rebuild the master key. */
  async prelogin(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email }, select: { status: true, kdfSalt: true, kdfParams: true } });
    if (user?.status === 'ACTIVE' && user.kdfSalt && user.kdfParams) {
      return { kdfSalt: user.kdfSalt, kdfParams: user.kdfParams };
    }
    // Unknown or inactive: a stable fake answer, so the response does not reveal whether the account exists.
    return { kdfSalt: fakeKdfSalt(this.config.getOrThrow<string>('SERVER_SECRET'), email), kdfParams: DEFAULT_KDF_PARAMS };
  }

  /** Step 2 of login: checks the verifier and starts a session. */
  async login(dto: LoginDto, meta: Meta, res: Response) {
    const user = await this.prisma.user.findUnique({ where: { email: dto.email } });
    const canLogin = user?.status === 'ACTIVE' && user.authVerifierHash !== null;
    // Same work whether or not the user exists, so timing does not reveal valid emails.
    const valid = await verifyVerifier(dto.authVerifier, canLogin ? user.authVerifierHash! : await dummyVerifierHash());

    if (!canLogin || !valid) {
      await this.audit.log('LOGIN_FAILED', { userId: user?.id ?? null, metadata: { email: dto.email, ...meta } });
      throw new UnauthorizedException('Invalid email or password');
    }

    await this.startSession(user.id, res);
    await this.audit.log('LOGIN', { userId: user.id, metadata: meta });
    return {
      user: { id: user.id, email: user.email, name: user.name },
      publicKey: user.publicKey,
      encryptedPrivateKey: user.encryptedPrivateKey,
    };
  }

  /** New access token. The refresh token is single-use: each refresh replaces it (rotation). */
  async refresh(refreshToken: string | undefined, res: Response): Promise<void> {
    if (!refreshToken) throw new UnauthorizedException();
    const stored = await this.prisma.refreshToken.findUnique({ where: { tokenHash: sha256(refreshToken) }, include: { user: true } });
    if (!stored) throw new UnauthorizedException();

    if (stored.revokedAt) {
      // An already-used token came back: someone may have copied it. End every session of this user.
      await this.revokeAll(stored.userId);
      throw new UnauthorizedException();
    }
    if (stored.expiresAt <= new Date() || stored.user.status !== 'ACTIVE') throw new UnauthorizedException();

    const claimed = await this.prisma.refreshToken.updateMany({
      where: { id: stored.id, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    if (claimed.count !== 1) throw new UnauthorizedException();
    await this.startSession(stored.userId, res);
  }

  async logout(refreshToken: string | undefined, res: Response): Promise<void> {
    if (refreshToken) {
      const stored = await this.prisma.refreshToken.findUnique({ where: { tokenHash: sha256(refreshToken) } });
      if (stored) {
        await this.prisma.refreshToken.updateMany({ where: { id: stored.id, revokedAt: null }, data: { revokedAt: new Date() } });
        await this.audit.log('LOGOUT', { userId: stored.userId });
      }
    }
    clearAuthCookies(res);
  }

  me(user: AuthUser) {
    return user;
  }

  private async startSession(userId: string, res: Response): Promise<void> {
    const accessToken = await this.jwt.signAsync({ sub: userId });
    const refreshToken = randomToken();
    await this.prisma.refreshToken.create({
      data: { userId, tokenHash: sha256(refreshToken), expiresAt: new Date(Date.now() + REFRESH_TTL_MS) },
    });
    setAuthCookies(res, accessToken, refreshToken);
  }

  private async revokeAll(userId: string): Promise<void> {
    await this.prisma.refreshToken.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: new Date() } });
  }
}
