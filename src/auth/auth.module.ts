import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { ConfirmationModule } from 'src/confirmation/confirmation.module';
import { SecurityModule } from 'src/security/security.module';
import { BcryptModule } from 'src/shared/bcrypt/bcrypt.module';
import { TokenModule } from 'src/shared/token/token.module';

@Module({
  imports: [ConfirmationModule, SecurityModule, BcryptModule, TokenModule],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
