import { Transform, Type } from 'class-transformer';
import {
  IsArray,
  IsBase64,
  IsEmail,
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsUUID,
  Max,
  MaxLength,
  Min,
  ValidateNested,
} from 'class-validator';

// The server cannot check what is inside the keys (they are encrypted in the browser), only that
// each field has the right shape and a sane size.
const KEY_MAX = 8192;

const normalizeEmail = ({ value }: { value: unknown }) =>
  typeof value === 'string' ? value.trim().toLowerCase() : value;

export class KdfParamsDto {
  @IsInt() @Min(1) version!: number;
  @IsInt() @Min(19456) @Max(1048576) memory!: number; // KiB; 19 MiB is the OWASP minimum for Argon2id
  @IsInt() @Min(1) @Max(10) iterations!: number;
  @IsInt() @Min(1) @Max(16) parallelism!: number;
}

/** What the browser creates for a user from the master password. */
export class KeyMaterialDto {
  @IsString() @IsNotEmpty() @MaxLength(KEY_MAX) publicKey!: string;
  @IsString() @IsNotEmpty() @MaxLength(KEY_MAX) encryptedPrivateKey!: string;
  @IsBase64() kdfSalt!: string;
  @ValidateNested() @Type(() => KdfParamsDto) kdfParams!: KdfParamsDto;
  @IsBase64() @MaxLength(512) authVerifier!: string;
}

/** The user's personal vault key, locked once for the user and once for the organization. */
export class PersonalVaultDto {
  @IsString() @IsNotEmpty() @MaxLength(KEY_MAX) encryptedVaultKey!: string;
  @IsString() @IsNotEmpty() @MaxLength(KEY_MAX) orgEncryptedVaultKey!: string;
}

export class OrganizationDto {
  @IsString() @IsNotEmpty() @MaxLength(200) name!: string;
  @IsString() @IsNotEmpty() @MaxLength(KEY_MAX) publicKey!: string;
  @IsString() @IsNotEmpty() @MaxLength(KEY_MAX) encryptedOrgPrivateKey!: string;
}

export class SetupDto extends KeyMaterialDto {
  @Transform(normalizeEmail) @IsEmail() @MaxLength(320) email!: string;
  @IsString() @IsNotEmpty() @MaxLength(200) name!: string;
  @ValidateNested() @Type(() => OrganizationDto) organization!: OrganizationDto;
  @ValidateNested() @Type(() => PersonalVaultDto) personalVault!: PersonalVaultDto;
}

export class RegisterDto extends KeyMaterialDto {
  @IsString() @IsNotEmpty() @MaxLength(100) token!: string;
  @ValidateNested() @Type(() => PersonalVaultDto) personalVault!: PersonalVaultDto;
}

export class PreloginDto {
  @Transform(normalizeEmail) @IsEmail() @MaxLength(320) email!: string;
}

export class LoginDto {
  @Transform(normalizeEmail) @IsEmail() @MaxLength(320) email!: string;
  @IsBase64() @MaxLength(512) authVerifier!: string;
}

export class CreateInvitationDto {
  @Transform(normalizeEmail) @IsEmail() @MaxLength(320) email!: string;
  @IsString() @IsNotEmpty() @MaxLength(200) name!: string;
  @IsOptional() @IsArray() @IsUUID('all', { each: true }) roleIds?: string[];
}
