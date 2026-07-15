import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

/**
 * Auth-plane client (privileged role, NOT subject to RLS).
 *
 * Only the pre-tenant bootstrap flows may use it: register, login, token
 * refresh, password reset and invitation acceptance — the moments where a
 * tenant context does not exist yet. Everything else goes through
 * TenantPrismaService. See docs/architecture/tenancy-and-rls.md.
 */
@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  async onModuleInit(): Promise<void> {
    await this.$connect();
  }

  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
  }
}
