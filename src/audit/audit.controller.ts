import { Controller, Get } from '@nestjs/common';
import { AuditLog } from '@prisma/client';
import { CurrentTenant } from '../common/decorators/current-tenant.decorator';
import { RequirePermission } from '../common/decorators/require-permission.decorator';
import { AuditService } from './audit.service';

@Controller('audit-logs')
export class AuditController {
  constructor(private readonly auditService: AuditService) {}

  @Get()
  @RequirePermission('audit:read')
  list(@CurrentTenant() tenantId: string): Promise<AuditLog[]> {
    return this.auditService.list(tenantId);
  }
}
