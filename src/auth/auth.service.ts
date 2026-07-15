import {
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Membership, Organization, Role, User } from '@prisma/client';
import * as argon2 from 'argon2';
import { createHash, randomBytes } from 'crypto';
import { AccessTokenPayload, AuthenticatedUser } from '../common/types/authenticated-user';
import { AuditService } from '../audit/audit.service';
import { MailService } from '../mail/mail.service';
import { PrismaService } from '../prisma/prisma.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { SwitchTenantDto } from './dto/switch-tenant.dto';

export interface AuthSession {
  accessToken: string;
  refreshToken: string;
  user: { id: string; name: string; email: string };
  organization: { id: string; name: string; slug: string };
  role: Role;
  organizations: { id: string; name: string; slug: string; role: Role }[];
}

type MembershipWithOrg = Membership & { organization: Organization };

const PASSWORD_RESET_PURPOSE = 'password-reset';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly config: ConfigService,
    private readonly mailService: MailService,
    private readonly auditService: AuditService,
  ) {}

  async register(dto: RegisterDto): Promise<AuthSession> {
    const passwordHash = await argon2.hash(dto.password);
    const slug = await this.availableSlug(dto.organizationName);

    // Auth plane: user + tenant + owner membership are born together,
    // before any tenant context exists.
    const membership = await this.prisma.$transaction(async (tx) => {
      const user = await tx.user.create({
        data: { name: dto.name, email: dto.email.toLowerCase(), passwordHash },
      });
      const organization = await tx.organization.create({
        data: { name: dto.organizationName, slug },
      });
      return tx.membership.create({
        data: {
          userId: user.id,
          organizationId: organization.id,
          role: Role.OWNER,
        },
        include: { organization: true, user: true },
      });
    });

    await this.auditService.log(
      membership.organizationId,
      'auth.register',
      membership.user.email,
      `User registered and organization "${membership.organization.name}" created`,
    );

    return this.createSession(membership.user, membership);
  }

  async login(dto: LoginDto): Promise<AuthSession> {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email.toLowerCase() },
    });
    // Same error whether the email or the password is wrong — no user enumeration.
    if (!user || !(await argon2.verify(user.passwordHash, dto.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const memberships = await this.membershipsOf(user.id);
    const membership = dto.organizationId
      ? memberships.find((m) => m.organizationId === dto.organizationId)
      : memberships[0];
    if (!membership) {
      throw new ForbiddenException('You are not a member of this organization');
    }

    await this.auditService.log(
      membership.organizationId,
      'auth.login',
      user.email,
      'Login successful',
    );

    return this.createSession(user, membership, memberships);
  }

  async refresh(refreshToken: string): Promise<AuthSession> {
    const stored = await this.prisma.refreshToken.findUnique({
      where: { tokenHash: this.hashToken(refreshToken) },
      include: { user: true },
    });
    if (!stored) {
      throw new UnauthorizedException('Invalid refresh token');
    }
    if (stored.revokedAt) {
      // Reuse of a rotated token means it may be stolen: kill the whole family.
      await this.prisma.refreshToken.updateMany({
        where: { userId: stored.userId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      throw new UnauthorizedException('Refresh token reuse detected');
    }
    if (stored.expiresAt < new Date()) {
      throw new UnauthorizedException('Refresh token expired');
    }

    const memberships = await this.membershipsOf(stored.userId);
    const membership = memberships.find(
      (m) => m.organizationId === stored.organizationId,
    );
    if (!membership) {
      throw new UnauthorizedException('Membership no longer exists');
    }

    await this.prisma.refreshToken.update({
      where: { id: stored.id },
      data: { revokedAt: new Date() },
    });

    return this.createSession(stored.user, membership, memberships);
  }

  async logout(refreshToken: string): Promise<void> {
    await this.prisma.refreshToken.updateMany({
      where: { tokenHash: this.hashToken(refreshToken), revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  async switchTenant(
    current: AuthenticatedUser,
    dto: SwitchTenantDto,
  ): Promise<AuthSession> {
    const memberships = await this.membershipsOf(current.userId);
    const membership = memberships.find(
      (m) => m.organizationId === dto.organizationId,
    );
    if (!membership) {
      throw new ForbiddenException('You are not a member of this organization');
    }
    if (dto.refreshToken) {
      await this.logout(dto.refreshToken);
    }
    return this.createSession(membership.user, membership, memberships);
  }

  async me(current: AuthenticatedUser): Promise<Omit<AuthSession, 'accessToken' | 'refreshToken'>> {
    const memberships = await this.membershipsOf(current.userId);
    const membership = memberships.find(
      (m) => m.organizationId === current.tenantId,
    );
    if (!membership) {
      throw new UnauthorizedException('Membership no longer exists');
    }
    return {
      user: {
        id: membership.user.id,
        name: membership.user.name,
        email: membership.user.email,
      },
      organization: {
        id: membership.organization.id,
        name: membership.organization.name,
        slug: membership.organization.slug,
      },
      role: membership.role,
      organizations: memberships.map((m) => ({
        id: m.organization.id,
        name: m.organization.name,
        slug: m.organization.slug,
        role: m.role,
      })),
    };
  }

  async updateProfile(
    current: AuthenticatedUser,
    name: string,
  ): Promise<{ id: string; name: string; email: string }> {
    const user = await this.prisma.user.update({
      where: { id: current.userId },
      data: { name },
    });
    await this.auditService.log(
      current.tenantId,
      'user.update',
      user.email,
      `Profile name changed to "${name}"`,
    );
    return { id: user.id, name: user.name, email: user.email };
  }

  async deleteAccount(current: AuthenticatedUser): Promise<void> {
    const ownedOrgs = await this.prisma.membership.findMany({
      where: { userId: current.userId, role: Role.OWNER },
      include: {
        organization: { include: { _count: { select: { memberships: true } } } },
      },
    });
    const orgWithMembers = ownedOrgs.find(
      (m) => m.organization._count.memberships > 1,
    );
    if (orgWithMembers) {
      throw new ForbiddenException(
        `You own "${orgWithMembers.organization.name}", which still has other members. Remove them first.`,
      );
    }
    await this.prisma.$transaction([
      // Solo-owned organizations die with the account; memberships,
      // invitations, audit logs and tokens go via ON DELETE CASCADE.
      this.prisma.organization.deleteMany({
        where: { id: { in: ownedOrgs.map((m) => m.organizationId) } },
      }),
      this.prisma.user.delete({ where: { id: current.userId } }),
    ]);
  }

  async requestPasswordReset(email: string): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });
    // Always succeed from the caller's point of view — no user enumeration.
    if (!user) {
      return;
    }
    const token = await this.jwtService.signAsync(
      { sub: user.id, purpose: PASSWORD_RESET_PURPOSE },
      { expiresIn: '15m' },
    );
    const frontendUrl = this.config.get<string>('FRONTEND_URL') ?? 'http://localhost:5173';
    await this.mailService.send(
      user.email,
      'Password Reset',
      `Click the following link to reset your password: ${frontendUrl}/reset-password?token=${token}`,
    );
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    let payload: { sub: string; purpose?: string };
    try {
      payload = await this.jwtService.verifyAsync(token);
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }
    if (payload.purpose !== PASSWORD_RESET_PURPOSE) {
      throw new UnauthorizedException('Invalid or expired token');
    }
    const passwordHash = await argon2.hash(newPassword);
    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: payload.sub },
        data: { passwordHash },
      }),
      // A reset invalidates every open session.
      this.prisma.refreshToken.updateMany({
        where: { userId: payload.sub, revokedAt: null },
        data: { revokedAt: new Date() },
      }),
    ]);
  }

  async createSession(
    user: User,
    membership: MembershipWithOrg,
    memberships?: MembershipWithOrg[],
  ): Promise<AuthSession> {
    const payload: AccessTokenPayload = {
      sub: user.id,
      email: user.email,
      tenantId: membership.organizationId,
      role: membership.role,
    };
    const accessToken = await this.jwtService.signAsync(payload);
    const refreshToken = await this.issueRefreshToken(
      user.id,
      membership.organizationId,
    );
    const all = memberships ?? [membership];
    return {
      accessToken,
      refreshToken,
      user: { id: user.id, name: user.name, email: user.email },
      organization: {
        id: membership.organization.id,
        name: membership.organization.name,
        slug: membership.organization.slug,
      },
      role: membership.role,
      organizations: all.map((m) => ({
        id: m.organization.id,
        name: m.organization.name,
        slug: m.organization.slug,
        role: m.role,
      })),
    };
  }

  private membershipsOf(
    userId: string,
  ): Promise<(MembershipWithOrg & { user: User })[]> {
    return this.prisma.membership.findMany({
      where: { userId },
      include: { organization: true, user: true },
      orderBy: { createdAt: 'asc' },
    });
  }

  private async issueRefreshToken(
    userId: string,
    organizationId: string,
  ): Promise<string> {
    const token = randomBytes(48).toString('hex');
    const ttlDays = Number(this.config.get('REFRESH_TOKEN_TTL_DAYS') ?? 7);
    await this.prisma.refreshToken.create({
      data: {
        tokenHash: this.hashToken(token),
        userId,
        organizationId,
        expiresAt: new Date(Date.now() + ttlDays * 24 * 60 * 60 * 1000),
      },
    });
    return token;
  }

  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
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
