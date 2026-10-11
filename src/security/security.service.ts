import {
  BadGatewayException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma-database/prisma.service';
import RequestWithId from 'src/common/entities/IRequestWithId';
import { User } from 'generated/prisma';
import { ConfirmationService } from 'src/confirmation/confirmation.service';
import { LETTER_TEMPLATES } from 'src/common/globals';
import { Request } from 'express';
import { BcryptService } from 'src/shared/bcrypt/bcrypt.service';
import { IPService } from 'src/shared/ip/ip.service';
import type IIpInfo from 'src/shared/ip/entities/IIpInfo';

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
    const { id, visitorId } = req;

    const user = await this.findUserById(id); // Find user by id
    const twoFactorAuthEnabled = user.twoFactorAuthEnabled;

    await this.prismaService
      .$transaction(async (tx) => {
        const user = await tx.user.update({
          where: { id },
          data: {
            twoFactorAuthEnabled: !twoFactorAuthEnabled,
          },
        });

        if (user.twoFactorAuthEnabled) {
          const ipInfo = await this.ipService.getInfoFromIp(req);

          await tx.authLog.create({
            data: { userId: id, ...ipInfo },
          });
          if (visitorId) {
            await tx.trustedDevice.create({
              data: {
                userId: id,
                visitorId: await this.bcryptService.hash(visitorId),
              },
            });
          }
        } else {
          await tx.authLog.deleteMany({ where: { userId: id } });
          await tx.trustedDevice.deleteMany({ where: { userId: id } });
        }
      })
      .catch((error) => {
        throw new BadGatewayException(
          `Failed to toggle two-factor authentication: ${error.message}`,
        );
      });

    return {
      message: `Two-factor authentication has been successfully ${twoFactorAuthEnabled ? 'disabled' : 'enabled'}`,
    };
  }

  async twoFactorAuth(
    user: User,
    req: Request,
  ): Promise<true | { message: string; confirmationId: string }> {
    const ipInfo = await this.ipService.getInfoFromIp(req);
    // const visitorId = await this.prismaService.trustedDevice.findFirst({
    //   where: { userId: user.id, visitorId:  },
    // });
    // return this.verifyAuth(ipInfo, user, visitorId);
    return true;
  }

  // Checks if the sign-in allowed
  // private async verifyAuth(
  //   ipInfo: IIpInfo | null,
  //   { id, email }: User,
  //   visitorId: { visitorId: string } | null,
  // ): Promise<true | { message: string; confirmationId: string }> {
  //   // Case 1: country = null & no previous 2FA country
  //   if (!ipInfo && !twoFactorCountry) return true; // Authorization allowed

  //   // Case 2: country = null & 2FA country exists -> suspicious
  //   if (!ipInfo && twoFactorCountry)
  //     // Create confirmation record && send token via email sender
  //     return this.sendTwoFactorAuthConfirmation(id, email); // Authorization not allowed

  //   // Case 3: country provided, but no stored 2FA country -> set it
  //   if (ipInfo && !twoFactorCountry) {
  //     const hashedCountry = await this.bcryptService.hash(ipInfo); // Get hashed country
  //     await this.prismaService.user.update({
  //       where: { id },
  //       data: { twoFactorCountry: hashedCountry },
  //     }); // Change user's two-factor auth country
  //     return true; // Authorization allowed
  //   }

  //   // Case 4: country provided, 2FA country exists -> compare
  //   const isMatch = await this.bcryptService.compare(ipInfo, twoFactorCountry); // Compare countries via bcrypt
  //   return isMatch ? true : this.sendTwoFactorAuthConfirmation(id, email);
  // }

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
