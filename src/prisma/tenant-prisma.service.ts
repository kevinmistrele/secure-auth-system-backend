import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { Prisma, PrismaClient } from '@prisma/client';

/**
 * Tenant-plane client. Connects as the RLS-enforced `app_user` role, so the
 * database itself refuses to return rows from another tenant — even if a
 * query forgets its WHERE clause.
 *
 * `set_config(..., true)` is transaction-local (the SET LOCAL equivalent):
 * with pooled connections a plain per-connection SET would leak the tenant of
 * one request into the next, so the tenant context is bound to a transaction
 * instead (ADR 0002).
 */
@Injectable()
export class TenantPrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  constructor() {
    super({
      datasources: {
        db: { url: process.env.APP_DATABASE_URL ?? process.env.DATABASE_URL },
      },
    });
  }

  async onModuleInit(): Promise<void> {
    await this.$connect();
  }

  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
  }

  withTenant<T>(
    tenantId: string,
    fn: (tx: Prisma.TransactionClient) => Promise<T>,
  ): Promise<T> {
    return this.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT set_config('app.current_tenant', ${tenantId}, true)`;
      return fn(tx);
    });
  }
}
