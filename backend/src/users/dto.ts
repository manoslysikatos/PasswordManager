import { Type } from 'class-transformer';
import { ArrayUnique, IsArray, IsNotEmpty, IsOptional, IsString, IsUUID, MaxLength, ValidateNested } from 'class-validator';
import { KEY_MAX } from '../auth/dto.js';

/** A vault key, locked in the admin's browser with the user's public key. */
export class WrappedVaultKeyDto {
  @IsUUID() vaultId!: string;
  @IsString() @IsNotEmpty() @MaxLength(KEY_MAX) encryptedVaultKey!: string;
}

/**
 * The role, plus the keys the user needs to actually use it, so policy and crypto change together:
 * - `encryptedOrgPrivateKey`: when the role brings ORG_ADMIN and the user does not have the org key yet
 * - `vaultKeys`: one for each vault the role opens
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
