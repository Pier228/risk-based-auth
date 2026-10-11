import { Module } from '@nestjs/common';
import { TokenService } from './token.service';
import { IPModule } from '../ip/ip.module';

@Module({
  imports: [IPModule],
  providers: [TokenService],
  exports: [TokenService],
})
export class TokenModule {}
