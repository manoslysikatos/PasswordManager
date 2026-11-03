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
