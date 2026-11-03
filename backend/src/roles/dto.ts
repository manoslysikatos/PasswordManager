import { Transform } from 'class-transformer';
import { ArrayUnique, IsArray, IsEnum, IsNotEmpty, IsOptional, IsString, MaxLength } from 'class-validator';
import { Permission } from '../generated/prisma/client.js';

const trim = ({ value }: { value: unknown }) => (typeof value === 'string' ? value.trim() : value);

export class CreateRoleDto {
  @Transform(trim) @IsString() @IsNotEmpty() @MaxLength(100) name!: string;
  @IsOptional() @IsString() @MaxLength(500) description?: string;
  @IsArray() @ArrayUnique() @IsEnum(Permission, { each: true }) permissions!: Permission[];
}

/** Every field is optional; `permissions`, when sent, replaces the whole list. */
export class UpdateRoleDto {
  @IsOptional() @Transform(trim) @IsString() @IsNotEmpty() @MaxLength(100) name?: string;
  @IsOptional() @IsString() @MaxLength(500) description?: string;
  @IsOptional() @IsArray() @ArrayUnique() @IsEnum(Permission, { each: true }) permissions?: Permission[];
}
