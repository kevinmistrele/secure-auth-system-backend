import { Injectable, Logger } from '@nestjs/common';
import { AuditLog } from '@prisma/client';
import { TenantPrismaService } from '../prisma/tenant-prisma.service';

/**
 * Tenant-scoped audit trail. Always writes through the RLS-enforced client:
 * the WITH CHECK policy guarantees a log row can only land in the tenant it
 * claims to belong to.
 */
@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  constructor(private readonly tenantPrisma: TenantPrismaService) {}

  async log(
    tenantId: string,
    action: string,
    actorEmail: string,
    details: string,
  ): Promise<void> {
    try {
      await this.tenantPrisma.withTenant(tenantId, (tx) =>
        tx.auditLog.create({
          data: { organizationId: tenantId, action, actorEmail, details },
        }),
      );
    } catch (error) {
      // Auditing must never take the main flow down with it.
      this.logger.error(`Failed to write audit log for ${action}`, error);
    }
  }

  list(tenantId: string): Promise<AuditLog[]> {
    return this.tenantPrisma.withTenant(tenantId, (tx) =>
      tx.auditLog.findMany({ orderBy: { createdAt: 'desc' }, take: 100 }),
    );
  }
}
