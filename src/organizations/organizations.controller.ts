import { Body, Controller, Get, Patch, Post } from '@nestjs/common';
import { Organization } from '@prisma/client';
import { CurrentTenant } from '../common/decorators/current-tenant.decorator';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { RequirePermission } from '../common/decorators/require-permission.decorator';
import { AuthenticatedUser } from '../common/types/authenticated-user';
import {
  CreateOrganizationDto,
  UpdateOrganizationDto,
} from './dto/organization.dto';
import {
  OrganizationsService,
  OrganizationSummary,
} from './organizations.service';

@Controller('organizations')
export class OrganizationsController {
  constructor(private readonly organizationsService: OrganizationsService) {}

  @Post()
  create(
    @CurrentUser() user: AuthenticatedUser,
    @Body() dto: CreateOrganizationDto,
  ): Promise<OrganizationSummary> {
    return this.organizationsService.create(user, dto.name);
  }

  @Get()
  listMine(
    @CurrentUser() user: AuthenticatedUser,
  ): Promise<OrganizationSummary[]> {
    return this.organizationsService.listMine(user.userId);
  }

  @Get('current')
  @RequirePermission('org:read')
  getCurrent(@CurrentTenant() tenantId: string): Promise<Organization> {
    return this.organizationsService.getCurrent(tenantId);
  }

  @Patch('current')
  @RequirePermission('org:update')
  rename(
    @CurrentTenant() tenantId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body() dto: UpdateOrganizationDto,
  ): Promise<Organization> {
    return this.organizationsService.rename(tenantId, user, dto.name);
  }
}
