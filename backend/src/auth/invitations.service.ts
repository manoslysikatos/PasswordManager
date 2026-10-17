import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuditService } from '../audit/audit.service.js';
import type { AuthUser } from '../common/auth.decorators.js';
import { hashVerifier, randomToken, sha256 } from '../common/crypto.js';
import { PrismaService } from '../prisma/prisma.service.js';
import type { CreateInvitationDto, RegisterDto } from './dto.js';
import { createPersonalVault } from './personal-vault.js';

const INVITATION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

@Injectable()
export class InvitationsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly config: ConfigService,
  ) {}

  /** Creates (or re-sends) an invitation. The admin copies the returned link to the new user. */
  async create(dto: CreateInvitationDto, invitedBy: AuthUser) {
    const existing = await this.prisma.user.findUnique({ where: { email: dto.email } });
    if (existing && existing.status !== 'INVITED') {
      throw new ConflictException('A user with this email already exists');
    }
    const roleIds = dto.roleIds ?? [];
    if (roleIds.length > 0 && (await this.prisma.role.count({ where: { id: { in: roleIds } } })) !== roleIds.length) {
      throw new BadRequestException('Unknown role');
    }

    const token = randomToken();
    const expiresAt = new Date(Date.now() + INVITATION_TTL_MS);
    const user = await this.prisma.$transaction(async (tx) => {
      const invited = existing ?? (await tx.user.create({ data: { email: dto.email, name: dto.name, status: 'INVITED' } }));
      // A new link replaces any earlier one that was not used.
      await tx.invitation.updateMany({ where: { userId: invited.id, acceptedAt: null }, data: { expiresAt: new Date() } });
      await tx.invitation.create({ data: { userId: invited.id, tokenHash: sha256(token), invitedById: invitedBy.id, expiresAt } });
      if (roleIds.length > 0) {
        await tx.userRole.createMany({ data: roleIds.map((roleId) => ({ userId: invited.id, roleId })), skipDuplicates: true });
      }
      return invited;
    });

    await this.audit.log('USER_INVITED', { userId: invitedBy.id, targetType: 'user', targetId: user.id });
    const appUrl = this.config.get<string>('APP_URL') ?? 'http://localhost:5173';
    return { userId: user.id, inviteUrl: `${appUrl}/invite/${token}`, expiresAt };
  }

  /** What the registration page needs: who is invited, and the org public key to lock the personal vault key. */
  async describe(token: string) {
    const invitation = await this.findValid(token);
    const organization = await this.prisma.organization.findFirst({ select: { name: true, publicKey: true } });
    if (!organization) throw new NotFoundException('Invitation not found');
    return { email: invitation.user.email, name: invitation.user.name, organization };
  }

  /** Accepts the invitation: stores the keys created in the browser and activates the user. */
  async accept(dto: RegisterDto): Promise<{ userId: string }> {
    const invitation = await this.findValid(dto.token);
    const authVerifierHash = await hashVerifier(dto.authVerifier);

    await this.prisma.$transaction(async (tx) => {
      // Guards against using the same link twice at the same moment.
      const claimed = await tx.invitation.updateMany({
        where: { id: invitation.id, acceptedAt: null },
        data: { acceptedAt: new Date() },
      });
      if (claimed.count !== 1) throw new BadRequestException('Invalid or expired invitation');

      await tx.user.update({
        where: { id: invitation.userId },
        data: {
          status: 'ACTIVE',
          publicKey: dto.publicKey,
          encryptedPrivateKey: dto.encryptedPrivateKey,
          kdfSalt: dto.kdfSalt,
          kdfParams: { ...dto.kdfParams },
          authVerifierHash,
        },
      });
      await createPersonalVault(tx, invitation.userId, dto.personalVault);
    });

    await this.audit.log('USER_ACTIVATED', { userId: invitation.userId, targetType: 'user', targetId: invitation.userId });
    return { userId: invitation.userId };
  }

  private async findValid(token: string) {
    const invitation = await this.prisma.invitation.findUnique({ where: { tokenHash: sha256(token) }, include: { user: true } });
    if (!invitation || invitation.acceptedAt || invitation.expiresAt <= new Date() || invitation.user.status !== 'INVITED') {
      throw new BadRequestException('Invalid or expired invitation');
    }
    return invitation;
  }
}
