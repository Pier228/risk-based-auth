import { Module } from '@nestjs/common';
import { IPService } from './ip.service';
import { BcryptModule } from '../bcrypt/bcrypt.module';

@Module({
  imports: [BcryptModule],
  providers: [IPService],
  exports: [IPService],
})
export class IPModule {}
