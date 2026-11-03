import { Body, Controller, Delete, Get, Param, ParseUUIDPipe, Patch, Post } from '@nestjs/common';
import { type AuthUser, CurrentUser, RequirePermission } from '../common/auth.decorators.js';
import { CreateVaultDto, GrantRoleDto, RenameVaultDto, RoleAccessDto } from './dto.js';
import { VaultsService } from './vaults.service.js';

// Managing a group (rename, roles) needs no permission of its own: it is allowed to the vault's owner
// and to org admins, which VaultsService checks per vault.
@Controller('vaults')
export class VaultsController {
  constructor(private readonly vaults: VaultsService) {}

  @Get()
  listMine(@CurrentUser() user: AuthUser) {
    return this.vaults.listMine(user);
  }

  @RequirePermission('ORG_ADMIN')
  @Get('all')
  listAll() {
    return this.vaults.listAll();
  }

  @RequirePermission('CREATE_GROUPS')
  @Post()
  create(@Body() dto: CreateVaultDto, @CurrentUser() user: AuthUser) {
    return this.vaults.create(dto, user);
  }

  @Patch(':id')
  rename(@Param('id', ParseUUIDPipe) id: string, @Body() dto: RenameVaultDto, @CurrentUser() user: AuthUser) {
    return this.vaults.rename(id, dto, user);
  }

  @Post(':id/roles')
  grantRole(@Param('id', ParseUUIDPipe) id: string, @Body() dto: GrantRoleDto, @CurrentUser() user: AuthUser) {
    return this.vaults.grantRole(id, dto, user);
  }

  @Patch(':id/roles/:roleId')
  changeRoleAccess(
    @Param('id', ParseUUIDPipe) id: string,
    @Param('roleId', ParseUUIDPipe) roleId: string,
    @Body() dto: RoleAccessDto,
    @CurrentUser() user: AuthUser,
  ) {
    return this.vaults.changeRoleAccess(id, roleId, dto, user);
  }

  @Delete(':id/roles/:roleId')
  revokeRole(@Param('id', ParseUUIDPipe) id: string, @Param('roleId', ParseUUIDPipe) roleId: string, @CurrentUser() user: AuthUser) {
    return this.vaults.revokeRole(id, roleId, user);
  }
}
