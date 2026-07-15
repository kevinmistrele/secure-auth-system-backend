import { Injectable, NotFoundException } from '@nestjs/common';
import { Organization, Role } from '@prisma/client';
import { randomBytes } from 'crypto';
import { AuditService } from '../audit/audit.service';
import { AuthenticatedUser } from '../common/types/authenticated-user';
import { PrismaService } from '../prisma/prisma.service';
import { TenantPrismaService } from '../prisma/tenant-prisma.service';

export interface OrganizationSummary {
  id: string;
  name: string;
  slug: string;
  role: Role;
}

@Injectable()
export class OrganizationsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly tenantPrisma: TenantPrismaService,
    private readonly auditService: AuditService,
  ) {}

  /** Auth plane: a brand-new tenant has no tenant context yet. */
  async create(
    user: AuthenticatedUser,
    name: string,
  ): Promise<OrganizationSummary> {
    const slug = await this.availableSlug(name);
    const organization = await this.prisma.organization.create({
      data: {
        name,
        slug,
        memberships: { create: { userId: user.userId, role: Role.OWNER } },
      },
    });
    await this.auditService.log(
      organization.id,
      'organization.create',
      user.email,
      `Organization "${name}" created`,
    );
    return { id: organization.id, name, slug, role: Role.OWNER };
  }

  /** Auth plane: "which organizations am I in" is cross-tenant by design. */
  async listMine(userId: string): Promise<OrganizationSummary[]> {
    const memberships = await this.prisma.membership.findMany({
      where: { userId },
      include: { organization: true },
      orderBy: { createdAt: 'asc' },
    });
    return memberships.map((m) => ({
      id: m.organization.id,
      name: m.organization.name,
      slug: m.organization.slug,
      role: m.role,
    }));
  }

  async getCurrent(tenantId: string): Promise<Organization> {
    const organization = await this.tenantPrisma.withTenant(tenantId, (tx) =>
      tx.organization.findFirst(),
    );
    if (!organization) {
      throw new NotFoundException('Organization not found');
    }
    return organization;
  }

  async rename(
    tenantId: string,
    actor: AuthenticatedUser,
    name: string,
  ): Promise<Organization> {
    const organization = await this.tenantPrisma.withTenant(tenantId, (tx) =>
      tx.organization.update({ where: { id: tenantId }, data: { name } }),
    );
    await this.auditService.log(
      tenantId,
      'organization.rename',
      actor.email,
      `Organization renamed to "${name}"`,
    );
    return organization;
  }

  private async availableSlug(name: string): Promise<string> {
    const base =
      name
        .toLowerCase()
        .normalize('NFKD')
        .replace(/[̀-ͯ]/g, '')
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/(^-|-$)/g, '') || 'org';
    const existing = await this.prisma.organization.findUnique({
      where: { slug: base },
    });
    return existing ? `${base}-${randomBytes(3).toString('hex')}` : base;
  }
}
