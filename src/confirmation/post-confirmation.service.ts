import { Inject, Injectable } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { Response } from 'express';
import { Prisma, User } from 'generated/prisma';
import { PrismaService } from 'src/prisma-database/prisma.service';
import { IPService } from 'src/shared/ip/ip.service';
import { TokenService } from 'src/shared/token/token.service';
import type RequestWithId from 'src/common/entities/IRequestWithId';

@Injectable()
export class PostConfirmationService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly tokenService: TokenService,
    private readonly ipService: IPService,
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
  ) {}

  // Confirm the user's email address & set up access & refresh token inside cookies.
  async handleEmailVerification(
    id: string,
    response: Response,
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
      'User successfully confirmed email address',
    ); // Create and set auth cookies
  }

  // Confirm user's authorization
  async handleTwoFactorAuthorization(
    id: string,
    response: Response,
    request: RequestWithId,
    tx?: Prisma.TransactionClient,
  ): Promise<{ message: string }> {
    const prisma = tx ?? this.prisma; // Use tx(transaction prisma model) or prismaService
    const user = await prisma.user.findUnique({ where: { id } });

    if (user && !user.twoFactorAuthEnabled) {
      return this.authorizeUser(user, response); // Create and set auth cookies
    }

    // 1. Link new IP in AuthLog
    const ipInfo = await this.ipService.getInfoFromIp(request);

    if (ipInfo) {
      const isApiLinked = await prisma.authLog.findFirst({
        where: { userId: id, ip: ipInfo.ip },
      });

      if (!isApiLinked) {
        await prisma.authLog.create({
          data: { userId: id, ...ipInfo },
        });
      }
    }

    // 2. Add current device to TrustedDevice
    const visitorId =
      request.visitorId || (request.headers['x-visitor-id'] as string);
    if (visitorId) {
      const isDeviceLinked = await prisma.trustedDevice.findFirst({
        where: { userId: id, visitorId },
      });
      if (!isDeviceLinked) {
        await prisma.trustedDevice.create({
          data: { userId: id, visitorId },
        });
      }
    }

    // 3. Reset failed attempt counter in Redis
    await this.cacheManager.del(`failed_attempts:${id}`);

    return this.authorizeUser(user, response); // Create and set auth cookies
  }

  private async authorizeUser(
    user: User,
    response: Response,
    message?: string,
  ): Promise<{ message: string }> {
    await this.tokenService.setAuthCookies(user, response); // Create and set auth cookies
    return { message: message ?? 'User successfully authorized' };
  }
}