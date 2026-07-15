import {
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Invitation, Role } from '@prisma/client';
import { createHash, randomBytes } from 'crypto';
import { AuditService } from '../audit/audit.service';
import { AuthService, AuthSession } from '../auth/auth.service';
import { AuthenticatedUser } from '../common/types/authenticated-user';
import { MailService } from '../mail/mail.service';
import { PrismaService } from '../prisma/prisma.service';
import { TenantPrismaService } from '../prisma/tenant-prisma.service';

export type InvitationSummary = Omit<Invitation, 'tokenHash'>;

const INVITATION_TTL_DAYS = 7;

@Injectable()
export class InvitationsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly tenantPrisma: TenantPrismaService,
    private readonly mailService: MailService,
    private readonly auditService: AuditService,
    private readonly authService: AuthService,
    private readonly config: ConfigService,
  ) {}

  async create(
    tenantId: string,
    actor: AuthenticatedUser,
    email: string,
    role: Role,
  ): Promise<{ invitation: InvitationSummary; inviteLink: string }> {
    const normalizedEmail = email.toLowerCase();
    const token = randomBytes(32).toString('hex');

    const invitation = await this.tenantPrisma.withTenant(
      tenantId,
      async (tx) => {
        const existingMember = await tx.membership.findFirst({
          where: { user: { email: normalizedEmail } },
        });
        if (existingMember) {
          throw new ConflictException(
            'This email already belongs to a member of the organization',
          );
        }
        // Re-inviting replaces any previous pending invitation.
        await tx.invitation.deleteMany({
          where: { email: normalizedEmail, acceptedAt: null },
        });
        return tx.invitation.create({
          data: {
            email: normalizedEmail,
            organizationId: tenantId,
            role,
            tokenHash: this.hashToken(token),
            invitedById: actor.userId,
            expiresAt: new Date(
              Date.now() + INVITATION_TTL_DAYS * 24 * 60 * 60 * 1000,
            ),
          },
        });
      },
    );

    const frontendUrl =
      this.config.get<string>('FRONTEND_URL') ?? 'http://localhost:5173';
    const inviteLink = `${frontendUrl}/accept-invite?token=${token}`;
    await this.mailService.send(
      normalizedEmail,
      'You have been invited to an organization',
      `You were invited to join an organization. Accept here: ${inviteLink}`,
    );
    await this.auditService.log(
      tenantId,
      'invitation.create',
      actor.email,
      `Invited ${normalizedEmail} as ${role}`,
    );

    return { invitation: this.toSummary(invitation), inviteLink };
  }

  async listPending(tenantId: string): Promise<InvitationSummary[]> {
    const invitations = await this.tenantPrisma.withTenant(tenantId, (tx) =>
      tx.invitation.findMany({
        where: { acceptedAt: null, expiresAt: { gt: new Date() } },
        orderBy: { createdAt: 'desc' },
      }),
    );
    return invitations.map((i) => this.toSummary(i));
  }

  async revoke(tenantId: string, actor: AuthenticatedUser, id: string): Promise<void> {
    const revoked = await this.tenantPrisma.withTenant(tenantId, async (tx) => {
      const invitation = await tx.invitation.findFirst({ where: { id } });
      if (!invitation) {
        throw new NotFoundException('Invitation not found');
      }
      return tx.invitation.delete({ where: { id } });
    });
    await this.auditService.log(
      tenantId,
      'invitation.revoke',
      actor.email,
      `Invitation for ${revoked.email} revoked`,
    );
  }

  /**
   * Auth plane on purpose: the accepting user is not a member of the target
   * organization yet, so no tenant context can exist for this lookup.
   */
  async accept(user: AuthenticatedUser, token: string): Promise<AuthSession> {
    const invitation = await this.prisma.invitation.findUnique({
      where: { tokenHash: this.hashToken(token) },
      include: { organization: true },
    });
    if (!invitation || invitation.acceptedAt || invitation.expiresAt < new Date()) {
      throw new NotFoundException('Invitation not found or expired');
    }
    if (invitation.email !== user.email.toLowerCase()) {
      throw new ForbiddenException(
        'This invitation was issued for a different email address',
      );
    }

    const [, membership] = await this.prisma.$transaction([
      this.prisma.invitation.update({
        where: { id: invitation.id },
        data: { acceptedAt: new Date() },
      }),
      this.prisma.membership.create({
        data: {
          userId: user.userId,
          organizationId: invitation.organizationId,
          role: invitation.role,
        },
        include: { organization: true, user: true },
      }),
    ]);

    await this.auditService.log(
      invitation.organizationId,
      'invitation.accept',
      user.email,
      `${user.email} joined as ${invitation.role}`,
    );

    return this.authService.createSession(membership.user, membership);
  }

  private toSummary({ tokenHash: _tokenHash, ...rest }: Invitation): InvitationSummary {
    return rest;
  }

  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }
}
