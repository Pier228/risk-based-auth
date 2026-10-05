import { Module } from '@nestjs/common';
import { TokenService } from './token.service';
import { BcryptModule } from '../bcrypt/bcrypt.module';

@Module({
  imports: [BcryptModule],
  providers: [TokenService],
  exports: [TokenService],
})
export class TokenModule {}
