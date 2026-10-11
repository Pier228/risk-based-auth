import { Module } from '@nestjs/common';
import { TokenService } from './token.service';
import { IPModule } from '../ip/ip.module';
import { BcryptModule } from '../bcrypt/bcrypt.module';

@Module({
  imports: [IPModule, BcryptModule],
  providers: [TokenService],
  exports: [TokenService],
})
export class TokenModule {}
