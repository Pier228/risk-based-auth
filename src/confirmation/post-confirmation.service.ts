import { Injectable } from '@nestjs/common';
import { Request, Response } from 'express';
import { Prisma, User } from 'generated/prisma';
import { PrismaService } from 'src/prisma-database/prisma.service';
import { IPService } from 'src/shared/ip/ip.service';
import { TokenService } from 'src/shared/token/token.service';

@Injectable()
export class PostConfirmationService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly tokenService: TokenService,
    private readonly ipService: IPService,
  ) {}

  // Confirm the user's email address & set up access & refresh token inside cookies.
  async handleEmailVerification(
    id: string,
    response: Response,
    request: Request,
    tx?: Prisma.TransactionClient,
  ): Promise<{ message: string }> {
    const prisma = tx ?? this.prisma; // Use tx(transaction prisma model) or prismaService

    // User successfully confirm email address
    const user = await prisma.user.update({
      where: { id },
      data: { emailConfirmed: true },
    });

    return this.authorizeUser(
      user,
      response,
      request,
      'User successfully confirmed email address',
    ); // Create and set auth cookies
  }

  // Confirm user's authorization
  async handleTwoFactorAuthorization(
    id: string,
    response: Response,
    request: Request,
    tx?: Prisma.TransactionClient,
  ): Promise<{ message: string }> {
    const prisma = tx ?? this.prisma; // Use tx(transaction prisma model) or prismaService
    const user = await prisma.user.findUnique({ where: { id } });

    if (user && !user.twoFactorAuthEnabled) {
      return this.authorizeUser(user, response, request); // Create and set auth cookies
    }

    const hashedCountry = await this.ipService.getCountryByIp(request, true); // Get hashedCountry
    hashedCountry &&
      (await prisma.user.update({
        where: { id, twoFactorAuthEnabled: true },
        data: { twoFactorCountry: hashedCountry },
      }));

    return this.authorizeUser(user, response, request); // Create and set auth cookies
  }

  private async authorizeUser(
    user: User,
    response: Response,
    request: Request,
    message?: string,
  ): Promise<{ message: string }> {
    await this.tokenService.setAuthCookies(user, response, request); // Create and set auth cookies
    return { message: message ?? 'User successfully authorized' };
  }
}
