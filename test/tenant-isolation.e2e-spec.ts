import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { PrismaExceptionFilter } from '../src/common/filters/prisma-exception.filter';
import { PrismaService } from '../src/prisma/prisma.service';
import { TenantPrismaService } from '../src/prisma/tenant-prisma.service';

interface SessionBody {
  accessToken: string;
  refreshToken: string;
  user: { id: string; name: string; email: string };
  organization: { id: string; name: string; slug: string };
  role: string;
  organizations: { id: string; name: string; role: string }[];
}

/**
 * The single most important test in this repo: tenant A must never see
 * tenant B's data — enforced by Postgres RLS, not only by WHERE clauses.
 */
describe('Multi-tenant isolation (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let tenantPrisma: TenantPrismaService;

  let alice: SessionBody; // owner of Org A
  let bob: SessionBody; // owner of Org B
  let carolInOrgA: SessionBody; // invited into Org A as MEMBER

  const password = 'super-secret-password';

  const register = (
    name: string,
    email: string,
    organizationName: string,
  ): request.Test =>
    request(app.getHttpServer())
      .post('/api/auth/register')
      .send({ name, email, password, organizationName });

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();
    app.setGlobalPrefix('api');
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
    app.useGlobalFilters(new PrismaExceptionFilter());
    await app.init();

    prisma = app.get(PrismaService);
    tenantPrisma = app.get(TenantPrismaService);
    await prisma.$executeRawUnsafe(
      'TRUNCATE users, organizations RESTART IDENTITY CASCADE',
    );

    alice = (await register('Alice', 'alice@org-a.test', 'Org A').expect(201))
      .body as SessionBody;
    bob = (await register('Bob', 'bob@org-b.test', 'Org B').expect(201))
      .body as SessionBody;
  });

  afterAll(async () => {
    await app.close();
  });

  it('registers a user as OWNER of a fresh organization', () => {
    expect(alice.role).toBe('OWNER');
    expect(alice.organization.name).toBe('Org A');
    expect(alice.accessToken).toBeDefined();
  });

  it('logs in with tenant and role claims in the session', async () => {
    const res = await request(app.getHttpServer())
      .post('/api/auth/login')
      .send({ email: 'alice@org-a.test', password })
      .expect(200);
    const body = res.body as SessionBody;
    expect(body.organization.id).toBe(alice.organization.id);
    expect(body.role).toBe('OWNER');
  });

  it('rejects unauthenticated access to tenant data', async () => {
    await request(app.getHttpServer()).get('/api/members').expect(401);
  });

  describe('invitation flow', () => {
    let inviteLink: string;

    it('lets an OWNER invite an email as MEMBER', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/invitations')
        .set('Authorization', `Bearer ${alice.accessToken}`)
        .send({ email: 'carol@org-a.test', role: 'MEMBER' })
        .expect(201);
      inviteLink = (res.body as { inviteLink: string }).inviteLink;
      expect(inviteLink).toContain('token=');
    });

    it('creates a membership when the invited user accepts', async () => {
      const carol = (
        await register('Carol', 'carol@org-a.test', 'Carol Personal').expect(
          201,
        )
      ).body as SessionBody;
      const token = new URL(inviteLink).searchParams.get('token');
      const res = await request(app.getHttpServer())
        .post('/api/invitations/accept')
        .set('Authorization', `Bearer ${carol.accessToken}`)
        .send({ token })
        .expect(200);
      carolInOrgA = res.body as SessionBody;
      expect(carolInOrgA.organization.id).toBe(alice.organization.id);
      expect(carolInOrgA.role).toBe('MEMBER');
    });

    it('rejects accepting the same invitation twice', async () => {
      const token = new URL(inviteLink).searchParams.get('token');
      await request(app.getHttpServer())
        .post('/api/invitations/accept')
        .set('Authorization', `Bearer ${carolInOrgA.accessToken}`)
        .send({ token })
        .expect(404);
    });
  });

  describe('tenant isolation through the API', () => {
    it('shows each tenant only its own members', async () => {
      const orgA = await request(app.getHttpServer())
        .get('/api/members')
        .set('Authorization', `Bearer ${alice.accessToken}`)
        .expect(200);
      const orgB = await request(app.getHttpServer())
        .get('/api/members')
        .set('Authorization', `Bearer ${bob.accessToken}`)
        .expect(200);

      const emailsA = (orgA.body as { email: string }[]).map((m) => m.email);
      const emailsB = (orgB.body as { email: string }[]).map((m) => m.email);
      expect(emailsA.sort()).toEqual(['alice@org-a.test', 'carol@org-a.test']);
      expect(emailsB).toEqual(['bob@org-b.test']);
    });

    it('shows each tenant only its own audit trail', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/audit-logs')
        .set('Authorization', `Bearer ${bob.accessToken}`)
        .expect(200);
      const actors = (res.body as { actorEmail: string }[]).map(
        (l) => l.actorEmail,
      );
      expect(actors.length).toBeGreaterThan(0);
      expect(actors).not.toContain('alice@org-a.test');
    });

    it('refuses to switch to a tenant the user is not a member of', async () => {
      await request(app.getHttpServer())
        .post('/api/auth/switch-tenant')
        .set('Authorization', `Bearer ${bob.accessToken}`)
        .send({ organizationId: alice.organization.id })
        .expect(403);
    });

    it('hides members of other tenants behind a 404, not a 403', async () => {
      await request(app.getHttpServer())
        .patch(`/api/members/${bob.user.id}`)
        .set('Authorization', `Bearer ${alice.accessToken}`)
        .send({ role: 'ADMIN' })
        .expect(404);
    });
  });

  describe('RBAC', () => {
    it('denies a MEMBER the invitations:create permission', async () => {
      await request(app.getHttpServer())
        .post('/api/invitations')
        .set('Authorization', `Bearer ${carolInOrgA.accessToken}`)
        .send({ email: 'dave@org-a.test', role: 'MEMBER' })
        .expect(403);
    });

    it('denies a MEMBER the audit:read permission', async () => {
      await request(app.getHttpServer())
        .get('/api/audit-logs')
        .set('Authorization', `Bearer ${carolInOrgA.accessToken}`)
        .expect(403);
    });

    it('lets an OWNER promote a MEMBER to ADMIN', async () => {
      const res = await request(app.getHttpServer())
        .patch(`/api/members/${carolInOrgA.user.id}`)
        .set('Authorization', `Bearer ${alice.accessToken}`)
        .send({ role: 'ADMIN' })
        .expect(200);
      expect((res.body as { role: string }).role).toBe('ADMIN');
    });

    it('never lets the OWNER be demoted or removed', async () => {
      await request(app.getHttpServer())
        .patch(`/api/members/${alice.user.id}`)
        .set('Authorization', `Bearer ${carolInOrgA.accessToken}`)
        .send({ role: 'MEMBER' })
        .expect(403);
      await request(app.getHttpServer())
        .delete(`/api/members/${alice.user.id}`)
        .set('Authorization', `Bearer ${carolInOrgA.accessToken}`)
        .expect(403);
    });
  });

  describe('refresh token rotation and revocation', () => {
    it('rotates the refresh token and rejects reuse of the old one', async () => {
      const first = (
        await request(app.getHttpServer())
          .post('/api/auth/login')
          .send({ email: 'bob@org-b.test', password })
          .expect(200)
      ).body as SessionBody;

      await request(app.getHttpServer())
        .post('/api/auth/refresh')
        .send({ refreshToken: first.refreshToken })
        .expect(200);

      // Reusing the rotated token must fail — and revoke the family.
      await request(app.getHttpServer())
        .post('/api/auth/refresh')
        .send({ refreshToken: first.refreshToken })
        .expect(401);
    });

    it('rejects a revoked refresh token after logout', async () => {
      const session = (
        await request(app.getHttpServer())
          .post('/api/auth/login')
          .send({ email: 'bob@org-b.test', password })
          .expect(200)
      ).body as SessionBody;

      await request(app.getHttpServer())
        .post('/api/auth/logout')
        .send({ refreshToken: session.refreshToken })
        .expect(200);

      await request(app.getHttpServer())
        .post('/api/auth/refresh')
        .send({ refreshToken: session.refreshToken })
        .expect(401);
    });
  });

  describe('RLS at the database level (defense in depth)', () => {
    it('returns no foreign rows even for a query with no WHERE clause', async () => {
      const rows = await tenantPrisma.withTenant(
        bob.organization.id,
        (tx) => tx.membership.findMany(), // deliberately unfiltered
      );
      expect(rows.length).toBe(1);
      expect(rows.every((r) => r.organizationId === bob.organization.id)).toBe(
        true,
      );
    });

    it('returns nothing at all when no tenant context is set', async () => {
      const rows = await tenantPrisma.auditLog.findMany();
      expect(rows).toEqual([]);
    });

    it('refuses to write a row into another tenant', async () => {
      await expect(
        tenantPrisma.withTenant(bob.organization.id, (tx) =>
          tx.auditLog.create({
            data: {
              organizationId: alice.organization.id, // cross-tenant write
              action: 'evil.write',
              actorEmail: 'bob@org-b.test',
              details: 'should be blocked by the WITH CHECK policy',
            },
          }),
        ),
      ).rejects.toThrow();
    });
  });
});
