import { ForbiddenException, NotFoundException } from '@nestjs/common';
import type { Prisma } from '../generated/prisma/client.js';

type Db = Prisma.TransactionClient;

/** Holding a copy of the organization key is what lets an admin's browser open any vault. */
export async function hasOrgKey(db: Db, userId: string): Promise<boolean> {
  return (await db.orgKeyGrant.count({ where: { userId } })) > 0;
}

/** Vaults a user may manage (rename, connect to roles, lock keys for others): their own, or all with the org key. */
export async function manageableVaults(db: Db, userId: string): Promise<Prisma.VaultWhereInput> {
  if (await hasOrgKey(db, userId)) return {};
  return { keys: { some: { userId, viaRoleId: null, accessLevel: 'OWNER' } } };
}

export async function findManageableVault(db: Db, userId: string, vaultId: string) {
  const vault = await db.vault.findUnique({ where: { id: vaultId } });
  if (!vault) throw new NotFoundException('Vault not found');
  if ((await db.vault.count({ where: { AND: [{ id: vaultId }, await manageableVaults(db, userId)] } })) === 0) {
    throw new ForbiddenException('Only the owner of the vault or an organization admin can manage it');
  }
  return vault;
}
