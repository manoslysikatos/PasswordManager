import { Body, Controller, Delete, Get, HttpCode, Param, ParseUUIDPipe, Patch, Post } from '@nestjs/common';
import { type AuthUser, CurrentUser, RequirePermission } from '../common/auth.decorators.js';
import { CreateRoleDto, UpdateRoleDto } from './dto.js';
import { RolesService } from './roles.service.js';

@Controller('roles')
export class RolesController {
  constructor(private readonly roles: RolesService) {}

  // Reading is open to every signed-in user: role names are not secret inside the organization,
  // and admins with MANAGE_USERS need the list to assign roles.
  @Get()
  list() {
    return this.roles.list();
  }

  @Get('permissions')
  permissions() {
    return this.roles.allPermissions();
  }

  @RequirePermission('MANAGE_ROLES')
  @Post()
  create(@Body() dto: CreateRoleDto, @CurrentUser() user: AuthUser) {
    return this.roles.create(dto, user);
  }

  @RequirePermission('MANAGE_ROLES')
  @Patch(':id')
  update(@Param('id', ParseUUIDPipe) id: string, @Body() dto: UpdateRoleDto, @CurrentUser() user: AuthUser) {
    return this.roles.update(id, dto, user);
  }

  @RequirePermission('MANAGE_ROLES')
  @HttpCode(204)
  @Delete(':id')
  remove(@Param('id', ParseUUIDPipe) id: string, @CurrentUser() user: AuthUser) {
    return this.roles.remove(id, user);
  }
}
