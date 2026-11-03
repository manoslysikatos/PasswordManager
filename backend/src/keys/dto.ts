import { Type } from 'class-transformer';
import { IsArray, IsNotEmpty, IsOptional, IsString, IsUUID, MaxLength, ValidateNested } from 'class-validator';
import { KEY_MAX } from '../auth/dto.js';

export class PendingVaultKeyDto {
  @IsUUID() vaultId!: string;
  @IsUUID() userId!: string;
  @IsUUID() roleId!: string;
  @IsString() @IsNotEmpty() @MaxLength(KEY_MAX) encryptedVaultKey!: string;
}

export class PendingOrgKeyDto {
  @IsUUID() userId!: string;
  @IsString() @IsNotEmpty() @MaxLength(KEY_MAX) encryptedOrgPrivateKey!: string;
}

/** Keys locked in the browser for the requests returned by GET /keys/pending. */
export class FulfilKeysDto {
  @IsOptional() @IsArray() @ValidateNested({ each: true }) @Type(() => PendingVaultKeyDto) vaultKeys?: PendingVaultKeyDto[];
  @IsOptional() @IsArray() @ValidateNested({ each: true }) @Type(() => PendingOrgKeyDto) orgKeys?: PendingOrgKeyDto[];
}
