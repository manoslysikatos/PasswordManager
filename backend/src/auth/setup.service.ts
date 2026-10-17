import { ConflictException, Injectable } from '@nestjs/common';
import { Permission } from '../generated/prisma/client.js';
import { AuditService } from '../audit/audit.service.js';
import { hashVerifier } from '../common/crypto.js';
import { PrismaService } from '../prisma/prisma.service.js';
import type { SetupDto } from './dto.js';
import { createPersonalVault } from './personal-vault.js';

// First run: creates the first admin, the organization key and the Admin role.
// Allowed only while the database has no users.
@Injectable()
export class SetupService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  async needsSetup(): Promise<boolean> {
    return (await this.prisma.user.count()) === 0;
  }

  async setup(dto: SetupDto): Promise<{ userId: string }> {
    const authVerifierHash = await hashVerifier(dto.authVerifier);

    // Serializable + the count check: two simultaneous setup requests cannot both succeed.
    const user = await this.prisma.$transaction(
      async (tx) => {
        if ((await tx.user.count()) > 0 || (await tx.organization.count()) > 0) {
          throw new ConflictException('The system is already set up');
        }
        const admin = await tx.user.create({
          data: {
            email: dto.email,
            name: dto.name,
            status: 'ACTIVE',
            publicKey: dto.publicKey,
            encryptedPrivateKey: dto.encryptedPrivateKey,
            kdfSalt: dto.kdfSalt,
            kdfParams: { ...dto.kdfParams },
            authVerifierHash,
          },
        });
        await tx.organization.create({ data: { name: dto.organization.name, publicKey: dto.organization.publicKey } });
        await tx.orgKeyGrant.create({
          data: { userId: admin.id, encryptedOrgPrivateKey: dto.organization.encryptedOrgPrivateKey, grantedById: admin.id },
        });
        const adminRole = await tx.role.create({
          data: {
            name: 'Admin',
            description: 'Full access to the organization',
            permissions: { create: Object.values(Permission).map((permission) => ({ permission })) },
          },
        });
        await tx.userRole.create({ data: { userId: admin.id, roleId: adminRole.id } });
        await createPersonalVault(tx, admin.id, dto.personalVault);
        return admin;
      },
      { isolationLevel: 'Serializable' },
    );

    await this.audit.log('USER_ACTIVATED', { userId: user.id, targetType: 'user', targetId: user.id, metadata: { via: 'setup' } });
    return { userId: user.id };
  }
}
