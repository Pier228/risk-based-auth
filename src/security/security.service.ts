import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/prisma-database/prisma.service';
import RequestWithId from 'src/common/entities/IRequestWithId';
import { User } from 'generated/prisma';
import { ConfirmationService } from 'src/confirmation/confirmation.service';
import { LETTER_TEMPLATES } from 'src/common/globals';
import { Request } from 'express';
import { BcryptService } from 'src/shared/bcrypt/bcrypt.service';
import { IPService } from 'src/shared/ip/ip.service';

@Injectable()
export class SecurityService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly confirmationService: ConfirmationService,
    private readonly ipService: IPService,
    private readonly bcryptService: BcryptService,
  ) {}

  // Enable/Disable Two Factor Authentication for user
  async toggleTwoFactorAuth(req: RequestWithId): Promise<{ message: string }> {
    const { id } = req;
    
    const user = await this.findUserById(id); // Find user by id

    const twoFactorAuthEnabled = user.twoFactorAuthEnabled;
    const twoFactorCountry = twoFactorAuthEnabled
      ? null
      : await this.ipService.getCountryByIp(req, true); // Get hashed user's country by his ip address

    await this.prismaService.user.update({
      where: { id },
      data: { twoFactorAuthEnabled: !twoFactorAuthEnabled, twoFactorCountry },
    });

    return {
      message: `Two-factor authentication has been successfully ${twoFactorAuthEnabled ? 'disabled' : 'enabled'}`,
    };
  }

  // Compare the hashed country from the user record with the country from their IP
  async twoFactorAuth(
    user: User,
    req: Request,
  ): Promise<true | { message: string; confirmationId: string }> {
    const country = await this.ipService.getCountryByIp(req); // Get country from request
    return this.verifyAuth(country, user);
  }

  // Checks if the sign-in allowed
  private async verifyAuth(
    country: string | null,
    { twoFactorCountry, id, email }: User,
  ): Promise<true | { message: string; confirmationId: string }> {
    // Case 1: country = null & no previous 2FA country
    if (!country && !twoFactorCountry) return true; // Authorization allowed

    // Case 2: country = null & 2FA country exists -> suspicious
    if (!country && twoFactorCountry)
      // Create confirmation record && send token via email sender
      return this.sendTwoFactorAuthConfirmation(id, email); // Authorization not allowed

    // Case 3: country provided, but no stored 2FA country -> set it
    if (country && !twoFactorCountry) {
      const hashedCountry = await this.bcryptService.hash(country); // Get hashed country
      await this.prismaService.user.update({
        where: { id },
        data: { twoFactorCountry: hashedCountry },
      }); // Change user's two-factor auth country
      return true; // Authorization allowed
    }

    // Case 4: country provided, 2FA country exists -> compare
    const isMatch = await this.bcryptService.compare(country, twoFactorCountry); // Compare countries via bcrypt
    return isMatch ? true : this.sendTwoFactorAuthConfirmation(id, email);
  }

  // Create confirmation record and send confirmation letter via email
  private async sendTwoFactorAuthConfirmation(
    userId: string,
    email: string,
  ): Promise<{
    message: string;
    confirmationId: string;
  }> {
    // Check if the confirmation has already been requested
    const existingConfirmation =
      await this.prismaService.confirmation.findFirst({
        where: { userId, type: 'TWO_FACTOR_AUTH' },
      });

    // If confirmation has already been requested, resend it; if not, create and send a new confirmation
    const confirmationId = existingConfirmation
      ? await this.confirmationService.resendConfirmation(
          existingConfirmation.id,
        )
      : await this.confirmationService.createAndSendConfirmation({
          userId,
          type: 'TWO_FACTOR_AUTH',
          email,
          customerName: 'Dear Client',
          subject: LETTER_TEMPLATES.TWO_FACTOR_AUTH.subject,
          TemplateID: LETTER_TEMPLATES.TWO_FACTOR_AUTH.id,
        });

    return {
      message:
        'Suspicious activity detected. A verification code has been sent to your email. Please check your inbox and enter the code to proceed',
      confirmationId:
        typeof confirmationId === 'string'
          ? confirmationId
          : confirmationId.confirmationId,
    };
  }

  // Get user by id
  private async findUserById(id: string): Promise<User> {
    const user = await this.prismaService.user.findUnique({ where: { id } });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }
}
