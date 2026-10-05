import { Module } from '@nestjs/common';
import { SecurityService } from './security.service';
import { SecurityController } from './security.controller';
import { ConfirmationModule } from 'src/confirmation/confirmation.module';
import { BcryptModule } from 'src/shared/bcrypt/bcrypt.module';
import { IPModule } from 'src/shared/ip/ip.module';

@Module({
  imports: [ConfirmationModule, BcryptModule, IPModule],
  controllers: [SecurityController],
  providers: [SecurityService],
  exports: [SecurityService],
})
export class SecurityModule {}
