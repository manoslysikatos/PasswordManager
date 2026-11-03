import { Transform } from 'class-transformer';
import { IsIn, IsNotEmpty, IsString, IsUUID, MaxLength } from 'class-validator';
import { KEY_MAX } from '../auth/dto.js';

const trim = ({ value }: { value: unknown }) => (typeof value === 'string' ? value.trim() : value);

/** A new group. The browser makes a random vault key and locks it twice: for the creator, and for the organization. */
export class CreateVaultDto {
  @Transform(trim) @IsString() @IsNotEmpty() @MaxLength(100) name!: string;
  @IsString() @IsNotEmpty() @MaxLength(KEY_MAX) encryptedVaultKey!: string;
  @IsString() @IsNotEmpty() @MaxLength(KEY_MAX) orgEncryptedVaultKey!: string;
}

export class RenameVaultDto {
  @Transform(trim) @IsString() @IsNotEmpty() @MaxLength(100) name!: string;
}

/** OWNER belongs to whoever created the vault; roles get EDITOR (add and change) or VIEWER (read). */
export class RoleAccessDto {
  @IsIn(['EDITOR', 'VIEWER']) accessLevel!: 'EDITOR' | 'VIEWER';
}

export class GrantRoleDto extends RoleAccessDto {
  @IsUUID() roleId!: string;
}
