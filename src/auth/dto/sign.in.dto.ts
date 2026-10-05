import { ApiProperty, PickType } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';
import SignUpDTO from './sign.up.dto';

export default class SignInDTO extends PickType(SignUpDTO, ['email'] as const) {
  @ApiProperty({ example: 'P@ssw0rd123', description: 'User password' })
  @IsNotEmpty()
  @IsString()
  password: string;
}
