import { Type } from 'class-transformer';
import { ArrayUnique, IsArray, IsNotEmpty, IsOptional, IsString, IsUUID, MaxLength, ValidateNested } from 'class-validator';
import { KEY_MAX } from '../auth/dto.js';

/** A vault key, locked in the admin's browser with the user's public key. */
export class WrappedVaultKeyDto {
  @IsUUID() vaultId!: string;
  @IsString() @IsNotEmpty() @MaxLength(KEY_MAX) encryptedVaultKey!: string;
}

/**
 * The role, plus the keys the caller can already lock for the user (the rest stay pending):
 * - `encryptedOrgPrivateKey`: when the role brings ORG_ADMIN and the user does not have the org key yet
 * - `vaultKeys`: for vaults of the role that the caller manages
 */
export class AssignRoleDto {
  @IsUUID() roleId!: string;
  @IsOptional() @IsString() @IsNotEmpty() @MaxLength(KEY_MAX) encryptedOrgPrivateKey?: string;
  @IsOptional()
  @IsArray()
  @ArrayUnique((key: WrappedVaultKeyDto) => key.vaultId)
  @ValidateNested({ each: true })
  @Type(() => WrappedVaultKeyDto)
  vaultKeys?: WrappedVaultKeyDto[];
}
