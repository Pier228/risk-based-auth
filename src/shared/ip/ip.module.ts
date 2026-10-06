import { Module } from '@nestjs/common';
import { IPService } from './ip.service';

@Module({
  providers: [IPService],
  exports: [IPService],
})
export class IPModule {}
