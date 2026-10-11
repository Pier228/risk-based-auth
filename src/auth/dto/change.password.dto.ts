import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, MaxLength, MinLength } from 'class-validator';
import { USER_CONFIG } from 'src/common/globals';

export default class ChangePasswordDTO {
  @ApiProperty({
    example: 'OldP@ssw0rd123',
    description: 'Current user password',
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(USER_CONFIG.PASSWORD.minLength)
  @MaxLength(USER_CONFIG.PASSWORD.maxLength)
  currentPassword: string;

  @ApiProperty({
    example: 'NewStrongP@ssw0rd321',
    description: 'New user password',
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(USER_CONFIG.PASSWORD.minLength)
  @MaxLength(USER_CONFIG.PASSWORD.maxLength)
  newPassword: string;
}
