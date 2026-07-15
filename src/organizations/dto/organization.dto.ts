import { IsString, MaxLength, MinLength } from 'class-validator';

export class CreateOrganizationDto {
  @IsString()
  @MinLength(2)
  @MaxLength(100)
  name!: string;
}

export class UpdateOrganizationDto {
  @IsString()
  @MinLength(2)
  @MaxLength(100)
  name!: string;
}
