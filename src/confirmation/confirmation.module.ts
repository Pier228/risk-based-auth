import { Module } from '@nestjs/common';
import { ConfirmationService } from './confirmation.service';
import { EmailSenderModule } from 'src/shared/email-sender/email-sender.module';
import { ConfirmationController } from './confirmation.controller';
import { PostConfirmationService } from './post-confirmation.service';
import { BcryptModule } from 'src/shared/bcrypt/bcrypt.module';
import { IPModule } from 'src/shared/ip/ip.module';
import { TokenModule } from 'src/shared/token/token.module';

@Module({
  imports: [EmailSenderModule, BcryptModule, IPModule, TokenModule],
  controllers: [ConfirmationController],
  providers: [ConfirmationService, PostConfirmationService],
  exports: [ConfirmationService],
})
export class ConfirmationModule {}
