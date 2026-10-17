import type { Prisma } from '../generated/prisma/client.js';
import type { PersonalVaultDto } from './dto.js';

/** Every user gets a personal vault on activation, readable by the user and (via the org key) the admins. */
export function createPersonalVault(tx: Prisma.TransactionClient, ownerId: string, keys: PersonalVaultDto) {
  return tx.vault.create({
    data: {
      name: 'Personal',
      type: 'PERSONAL',
      ownerId,
      orgEncryptedVaultKey: keys.orgEncryptedVaultKey,
      keys: {
        create: { userId: ownerId, encryptedVaultKey: keys.encryptedVaultKey, accessLevel: 'OWNER', grantedById: ownerId },
      },
    },
  });
}
