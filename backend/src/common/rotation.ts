import type { Prisma } from '../generated/prisma/client.js';

/**
 * Decision 0009: when someone loses access, every credential they could open must be changed at its
 * service, because they may remember it. Adds one open RotationTask per credential, skipping those
 * that already have an open task for the same user. Returns how many were added.
 */
export async function flagForRotation(
  tx: Prisma.TransactionClient,
  credentials: Prisma.CredentialWhereInput,
  exposedUserId: string,
  triggeredById: string,
): Promise<number> {
  const exposed = await tx.credential.findMany({
    where: {
      AND: [
        credentials,
        // Still shared with the user directly: they keep access, so changing it now achieves nothing.
        { shares: { none: { userId: exposedUserId } } },
        { rotationTasks: { none: { exposedUserId, resolvedAt: null } } },
      ],
    },
    select: { id: true },
  });
  if (exposed.length === 0) return 0;
  await tx.rotationTask.createMany({
    data: exposed.map((credential) => ({ credentialId: credential.id, exposedUserId, triggeredById })),
  });
  return exposed.length;
}

/** Credentials in vaults the user can no longer open with a vault key (through a role, or directly). */
export const unreachableBy = (userId: string): Prisma.CredentialWhereInput => ({ vault: { keys: { none: { userId } } } });

/** An org admin can open every vault through the organization key, so losing one way in costs nothing. */
export async function isOrgAdmin(tx: Prisma.TransactionClient, userId: string): Promise<boolean> {
  return (await tx.rolePermission.count({ where: { permission: 'ORG_ADMIN', role: { users: { some: { userId } } } } })) > 0;
}
