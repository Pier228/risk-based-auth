import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, IsUUID, Length } from 'class-validator';

export default class VerifyConfirmationDTO {
  @ApiProperty({
    example: 'f1b3f995-64a7-4a6d-94e0-88f7bcf3aa5e',
    description: 'Confirmation uuid',
  })
  @IsNotEmpty()
  @IsString()
  @IsUUID()
  confirmationId: string;

  @ApiProperty({
    example: '092123',
    description: 'Confirmation token',
  })
  @IsNotEmpty()
  @IsString()
  @Length(6, 6)
  token: string;
}
