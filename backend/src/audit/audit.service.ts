import { Injectable } from '@nestjs/common';
import type { AuditAction } from '../generated/prisma/client.js';
import { PrismaService } from '../prisma/prisma.service.js';

export interface AuditEntry {
  userId?: string | null;
  targetType?: string;
  targetId?: string;
  metadata?: Record<string, string | number | boolean | null>;
}

@Injectable()
export class AuditService {
  constructor(private readonly prisma: PrismaService) {}

  async log(action: AuditAction, entry: AuditEntry = {}): Promise<void> {
    await this.prisma.auditLog.create({
      data: {
        action,
        userId: entry.userId ?? null,
        targetType: entry.targetType ?? null,
        targetId: entry.targetId ?? null,
        metadata: entry.metadata ?? undefined,
      },
    });
  }
}
