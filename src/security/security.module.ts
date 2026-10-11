import { Module } from '@nestjs/common';
import { SecurityService } from './security.service';
import { SecurityController } from './security.controller';
import { ConfirmationModule } from 'src/confirmation/confirmation.module';
import { IPModule } from 'src/shared/ip/ip.module';

@Module({
  imports: [ConfirmationModule, IPModule],
  controllers: [SecurityController],
  providers: [SecurityService],
  exports: [SecurityService],
})
export class SecurityModule {}
