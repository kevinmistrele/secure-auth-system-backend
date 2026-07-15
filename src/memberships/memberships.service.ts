import {
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { Prisma, Role } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthenticatedUser } from '../common/types/authenticated-user';
import { TenantPrismaService } from '../prisma/tenant-prisma.service';

export interface MemberSummary {
  userId: string;
  name: string;
  email: string;
  role: Role;
  joinedAt: Date;
}

@Injectable()
export class MembershipsService {
  constructor(
    private readonly tenantPrisma: TenantPrismaService,
    private readonly auditService: AuditService,
  ) {}

  async list(tenantId: string): Promise<MemberSummary[]> {
    const memberships = await this.tenantPrisma.withTenant(tenantId, (tx) =>
      tx.membership.findMany({
        include: { user: { select: { id: true, name: true, email: true } } },
        orderBy: { createdAt: 'asc' },
      }),
    );
    return memberships.map((m) => ({
      userId: m.user.id,
      name: m.user.name,
      email: m.user.email,
      role: m.role,
      joinedAt: m.createdAt,
    }));
  }

  async updateRole(
    tenantId: string,
    actor: AuthenticatedUser,
    targetUserId: string,
    role: Role,
  ): Promise<MemberSummary> {
    if (targetUserId === actor.userId) {
      throw new ForbiddenException('You cannot change your own role');
    }
    const updated = await this.tenantPrisma.withTenant(tenantId, async (tx) => {
      const membership = await this.findMember(tx, targetUserId);
      if (membership.role === Role.OWNER) {
        throw new ForbiddenException("The owner's role cannot be changed");
      }
      return tx.membership.update({
        where: { id: membership.id },
        data: { role },
        include: { user: { select: { id: true, name: true, email: true } } },
      });
    });
    await this.auditService.log(
      tenantId,
      'member.role_change',
      actor.email,
      `Role of ${updated.user.email} changed to ${role}`,
    );
    return {
      userId: updated.user.id,
      name: updated.user.name,
      email: updated.user.email,
      role: updated.role,
      joinedAt: updated.createdAt,
    };
  }

  async remove(
    tenantId: string,
    actor: AuthenticatedUser,
    targetUserId: string,
  ): Promise<void> {
    if (targetUserId === actor.userId) {
      throw new ForbiddenException('You cannot remove yourself');
    }
    const removed = await this.tenantPrisma.withTenant(tenantId, async (tx) => {
      const membership = await this.findMember(tx, targetUserId);
      if (membership.role === Role.OWNER) {
        throw new ForbiddenException('The owner cannot be removed');
      }
      return tx.membership.delete({
        where: { id: membership.id },
        include: { user: { select: { email: true } } },
      });
    });
    await this.auditService.log(
      tenantId,
      'member.remove',
      actor.email,
      `Member ${removed.user.email} removed`,
    );
  }

  private async findMember(
    tx: Prisma.TransactionClient,
    userId: string,
  ): Promise<{ id: string; role: Role }> {
    // RLS already narrows this to the current tenant; a cross-tenant user id
    // simply looks like it does not exist (404, never 403 — no info leak).
    const membership = await tx.membership.findFirst({
      where: { userId },
      select: { id: true, role: true },
    });
    if (!membership) {
      throw new NotFoundException('Member not found');
    }
    return membership;
  }
}
