import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Post,
} from '@nestjs/common';
import { AuthSession } from '../auth/auth.service';
import { CurrentTenant } from '../common/decorators/current-tenant.decorator';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { RequirePermission } from '../common/decorators/require-permission.decorator';
import { AuthenticatedUser } from '../common/types/authenticated-user';
import {
  AcceptInvitationDto,
  CreateInvitationDto,
} from './dto/invitation.dto';
import {
  InvitationsService,
  InvitationSummary,
} from './invitations.service';

@Controller('invitations')
export class InvitationsController {
  constructor(private readonly invitationsService: InvitationsService) {}

  @Post()
  @RequirePermission('invitations:create')
  create(
    @CurrentTenant() tenantId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body() dto: CreateInvitationDto,
  ): Promise<{ invitation: InvitationSummary; inviteLink: string }> {
    return this.invitationsService.create(tenantId, user, dto.email, dto.role);
  }

  @Get()
  @RequirePermission('invitations:read')
  listPending(@CurrentTenant() tenantId: string): Promise<InvitationSummary[]> {
    return this.invitationsService.listPending(tenantId);
  }

  @Delete(':id')
  @RequirePermission('invitations:revoke')
  async revoke(
    @CurrentTenant() tenantId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Param('id', ParseUUIDPipe) id: string,
  ): Promise<{ message: string }> {
    await this.invitationsService.revoke(tenantId, user, id);
    return { message: 'Invitation revoked' };
  }

  /** Any authenticated user may accept — membership in the target org is created here. */
  @HttpCode(200)
  @Post('accept')
  accept(
    @CurrentUser() user: AuthenticatedUser,
    @Body() dto: AcceptInvitationDto,
  ): Promise<AuthSession> {
    return this.invitationsService.accept(user, dto.token);
  }
}
