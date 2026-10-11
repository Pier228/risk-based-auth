import {
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { Response } from 'express';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma-database/prisma.service';
import { Token, User } from 'generated/prisma';
import {
  ACCESS_TOKEN_CONFIG,
  getCookieConfig,
  REFRESH_TOKEN_CONFIG,
  RISK_BASED_AUTH_CONFIG,
} from 'src/common/globals';
import type RequestWithId from 'src/common/entities/IRequestWithId';
import { IPService } from '../ip/ip.service';
import { calculateHaversineDistance } from 'src/common/utils/geo.util';

@Injectable()
export class TokenService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prismaService: PrismaService,
    private readonly ipService: IPService,
  ) {}

  async setAuthCookies(user: User, response: Response): Promise<void> {
    await this.createAndSetAccessToken(response, user.id);
    const tokenId = await this.createRefreshToken(user);
    this.setRefreshTokenCookie(response, tokenId);
  }

  async createAccessTokenUsingRefreshToken(
    req: RequestWithId,
    res: Response,
  ): Promise<void> {
    const refreshToken = req.signedCookies?.['refresh_token'];

    if (!refreshToken) {
      throw new UnauthorizedException('No valid token provided');
    }

    const tokenRecord = await this.getAndVerifyRefreshToken(refreshToken, res);

    // Background context check when 2FA is enabled
    if (tokenRecord.user.twoFactorAuthEnabled) {
      await this.verifyRefreshTokenContext(req, tokenRecord, res);
    }

    if (req.originalUrl.includes('/auth/sign-out')) {
      req.id = tokenRecord.userId;
      return;
    }

    // Rotation: revoke old refresh token, generate new one
    const [, newRefreshToken] = await Promise.all([
      this.prismaService.token.delete({ where: { id: tokenRecord.id } }),
      this.createRefreshToken(tokenRecord.user),
      this.createAndSetAccessToken(res, tokenRecord.userId),
    ]);

    this.setRefreshTokenCookie(res, newRefreshToken);
    req.id = tokenRecord.userId;
  }

  // Background session context validation (device + travel velocity)
  private async verifyRefreshTokenContext(
    request: RequestWithId,
    token: Token & { user: User },
    response: Response,
  ): Promise<void> {
    const visitorId =
      request.visitorId || (request.headers['x-visitor-id'] as string) || null;

    // 1. Trusted device verification
    const trustedDevices = await this.prismaService.trustedDevice.findMany({
      where: { userId: token.userId },
    });

    if (trustedDevices.length > 0) {
      if (!visitorId) {
        await this.clearCompromisedToken(response, token.id);
      }

      let isDeviceTrusted = false;
      for (const dev of trustedDevices) {
        if (dev.visitorId === visitorId) {
          isDeviceTrusted = true;
          break;
        }
      }

      if (!isDeviceTrusted) {
        await this.clearCompromisedToken(response, token.id);
      }
    }

    // 2. Impossible travel check during token refresh
    const ipInfo = await this.ipService.getInfoFromIp(request);
    if (ipInfo && ipInfo.lat != null && ipInfo.lon != null) {
      const latestAuthLog = await this.prismaService.authLog.findFirst({
        where: { userId: token.userId },
        orderBy: { createdAt: 'desc' },
      });

      if (
        latestAuthLog &&
        latestAuthLog.lat != null &&
        latestAuthLog.lon != null
      ) {
        const timeDiffHours =
          (Date.now() - new Date(latestAuthLog.createdAt).getTime()) /
          (1000 * 60 * 60);
        const minIntervalHours =
          RISK_BASED_AUTH_CONFIG.VELOCITY_LIMITS.MIN_TIME_INTERVAL_SECONDS /
          3600;

        if (timeDiffHours >= minIntervalHours) {
          const distanceKm = calculateHaversineDistance(
            latestAuthLog.lat,
            latestAuthLog.lon,
            ipInfo.lat,
            ipInfo.lon,
          );
          const speedKmh = distanceKm / timeDiffHours;
          if (
            speedKmh >
            RISK_BASED_AUTH_CONFIG.VELOCITY_LIMITS.MAX_REALISTIC_SPEED_KMH
          ) {
            await this.clearCompromisedToken(response, token.id);
          }
        }
      }
    }
  }

  private async createAndSetAccessToken(
    res: Response,
    userId: string,
  ): Promise<void> {
    const accessToken = await this.jwtService.signAsync({ id: userId });
    res.cookie(
      'access_token',
      accessToken,
      getCookieConfig(ACCESS_TOKEN_CONFIG.MAX_AGE),
    );
  }

  private setRefreshTokenCookie(res: Response, tokenId: string): void {
    res.cookie(
      'refresh_token',
      tokenId,
      getCookieConfig(REFRESH_TOKEN_CONFIG.MAX_AGE),
    );
  }

  private async createRefreshToken({ id }: User): Promise<string> {
    const expiresAt = new Date(Date.now() + REFRESH_TOKEN_CONFIG.MAX_AGE);
    try {
      const token = await this.prismaService.token.create({
        data: {
          userId: id,
          expiresAt,
        },
      });
      return token.id;
    } catch (err: any) {
      throw new InternalServerErrorException(
        `Failed to create refresh token: ${err.message}`,
      );
    }
  }

  private async getAndVerifyRefreshToken(
    id: string,
    res: Response,
  ): Promise<Token & { user: User }> {
    const token = await this.prismaService.token.findUnique({
      where: { id },
      include: { user: true },
    });

    if (!token) {
      this.clearRefreshTokenCookie(res, 'Invalid refresh token');
    }

    if (token.expiresAt < new Date()) {
      await this.prismaService.token.delete({ where: { id: token.id } });
      this.clearRefreshTokenCookie(res, 'Refresh token expired');
    }

    return token;
  }

  private clearRefreshTokenCookie(res: Response, message: string): never {
    res.clearCookie('refresh_token');
    throw new UnauthorizedException(message);
  }

  private async clearCompromisedToken(
    response: Response,
    id: string,
  ): Promise<never> {
    response.clearCookie('refresh_token');
    response.clearCookie('access_token');
    await this.prismaService.token.delete({ where: { id } }).catch(() => null);
    throw new UnauthorizedException(
      'Suspicious activity detected. Please sign-in again',
    );
  }
}
