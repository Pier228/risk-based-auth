import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';
import { USER_CONFIG } from 'src/common/globals';

export default class SignUpDTO {
  @ApiProperty({
    example: 'example@gmail.com',
    description: 'User email address',
  })
  @IsNotEmpty()
  @IsString()
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'P@ssw0rd123', description: 'User password' })
  @IsNotEmpty()
  @IsString()
  @MinLength(USER_CONFIG.PASSWORD.minLength)
  @MaxLength(USER_CONFIG.PASSWORD.maxLength)
  password: string;

  @ApiProperty({ example: 'Pier', description: 'User name' })
  @IsNotEmpty()
  @IsString()
  @MinLength(USER_CONFIG.NAME.minLength)
  @MaxLength(USER_CONFIG.NAME.maxLength)
  name: string;

  @ApiProperty({ example: 'Pasolini', description: 'User surname' })
  @IsNotEmpty()
  @IsString()
  @MinLength(USER_CONFIG.SURNAME.minLength)
  @MaxLength(USER_CONFIG.SURNAME.maxLength)
  surname: string;
}
