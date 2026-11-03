import { Body, Controller, Delete, Get, Param, ParseUUIDPipe, Post } from '@nestjs/common';
import { type AuthUser, CurrentUser, RequirePermission } from '../common/auth.decorators.js';
import { AssignRoleDto } from './dto.js';
import { UsersService } from './users.service.js';

@RequirePermission('MANAGE_USERS')
@Controller('users')
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @Get()
  list() {
    return this.users.list();
  }

  @Post(':id/roles')
  assignRole(@Param('id', ParseUUIDPipe) id: string, @Body() dto: AssignRoleDto, @CurrentUser() user: AuthUser) {
    return this.users.assignRole(id, dto, user);
  }

  @Delete(':id/roles/:roleId')
  removeRole(
    @Param('id', ParseUUIDPipe) id: string,
    @Param('roleId', ParseUUIDPipe) roleId: string,
    @CurrentUser() user: AuthUser,
  ) {
    return this.users.removeRole(id, roleId, user);
  }
}
