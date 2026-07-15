import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseUUIDPipe,
  Patch,
} from '@nestjs/common';
import { CurrentTenant } from '../common/decorators/current-tenant.decorator';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { RequirePermission } from '../common/decorators/require-permission.decorator';
import { AuthenticatedUser } from '../common/types/authenticated-user';
import { UpdateMemberRoleDto } from './dto/update-member-role.dto';
import { MembershipsService, MemberSummary } from './memberships.service';

@Controller('members')
export class MembershipsController {
  constructor(private readonly membershipsService: MembershipsService) {}

  @Get()
  @RequirePermission('members:read')
  list(@CurrentTenant() tenantId: string): Promise<MemberSummary[]> {
    return this.membershipsService.list(tenantId);
  }

  @Patch(':userId')
  @RequirePermission('members:update')
  updateRole(
    @CurrentTenant() tenantId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Param('userId', ParseUUIDPipe) userId: string,
    @Body() dto: UpdateMemberRoleDto,
  ): Promise<MemberSummary> {
    return this.membershipsService.updateRole(tenantId, user, userId, dto.role);
  }

  @Delete(':userId')
  @RequirePermission('members:remove')
  async remove(
    @CurrentTenant() tenantId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Param('userId', ParseUUIDPipe) userId: string,
  ): Promise<{ message: string }> {
    await this.membershipsService.remove(tenantId, user, userId);
    return { message: 'Member removed' };
  }
}
