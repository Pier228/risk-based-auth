import {
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma-database/prisma.service';
import { Token, User } from 'generated/prisma';
import { BcryptService } from '../bcrypt/bcrypt.service';
import {
  ACCESS_TOKEN_CONFIG,
  getCookieConfig,
  REFRESH_TOKEN_CONFIG,
} from 'src/common/globals';
import type RequestWithId from 'src/common/entities/IRequestWithId';

@Injectable()
export class TokenService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prismaService: PrismaService,
    private readonly bcryptService: BcryptService,
  ) {}

  // Set access & refresh tokens inside cookies
  async setAuthCookies(
    user: User,
    response: Response,
    request: Request,
  ): Promise<void> {
    await this.createAndSetAccessToken(response, user.id); // Generate and set JWT access token inside response cookies
    response.cookie(
      'refresh_token',
      await this.createRefreshToken(user, request),
      getCookieConfig(REFRESH_TOKEN_CONFIG.MAX_AGE),
    ); // Create and set refresh token inside cookies for the new user
  }

  // Generate a new access token from the refresh token
  async createAccessTokenUsingRefreshToken(
    req: RequestWithId,
    res: Response,
  ): Promise<void> {
    const refresh_token = req.signedCookies['refresh_token']; // Get refresh token

    if (!refresh_token) {
      throw new UnauthorizedException('No valid token provided');
    }

    const token = await this.getAndVerifyRefreshToken(refresh_token, res);

    token.user.twoFactorAuthEnabled &&
      (await this.verifyRefreshTokenContext(req, token, res)); // Checks if the generating new access token is allowed

    if (req.originalUrl.includes('/auth/sign-out')) return; // Prevent generating a new access token

    await this.createAndSetAccessToken(res, token.userId); // Generate and set new access token inside response cookies

    req.id = token.userId; // Set user id inside request body
  }

  // Two-factor auth for generating access token. Verify user's user-agent to generate new access token
  private async verifyRefreshTokenContext(
    request: RequestWithId,
    token: Token & { user: User },
    response: Response,
  ): Promise<void> {
    // Case 1: User-agent saved in refresh token record = null
    if (!token.twoFactorUserAgent) return; // Generating new access token is allowed

    const userAgent = request.headers['user-agent']; // Get user agent from request

    // Case 2: User-agent from request = null. Generating new access token isn't allowed
    !userAgent && (await this.clearCompromisedToken(response, token.id)); // Clear and delete compromised refresh token

    const isMatch = await this.bcryptService.compare(
      userAgent,
      token.twoFactorUserAgent,
    );

    // Case 3: User-agent from request and from refresh token record isn't match. Generating new access token isn't allowed
    !isMatch && (await this.clearCompromisedToken(response, token.id)); // Clear and delete compromised refresh token
  }

  // Generate and set JWT access token inside response cookies
  private async createAndSetAccessToken(
    res: Response,
    userId: string,
  ): Promise<void> {
    res.cookie(
      'access_token',
      await this.jwtService.signAsync({ id: userId }), // Signs a JWT token with the user's ID
      getCookieConfig(ACCESS_TOKEN_CONFIG.MAX_AGE),
    );
  }

  // Creates refresh token for user
  private async createRefreshToken(
    { id, twoFactorAuthEnabled }: User,
    request: Request,
  ): Promise<string> {
    const expiresAt = new Date(Date.now() + REFRESH_TOKEN_CONFIG.MAX_AGE);
    const twoFactorUserAgent =
      (twoFactorAuthEnabled && (await this.hashUserAgent(request))) || null;

    const token = await this.prismaService.token
      .create({
        data: {
          userId: id,
          expiresAt,
          twoFactorUserAgent,
        },
      })
      .catch((err) => {
        throw new InternalServerErrorException(
          'Failed to create refresh token. Error message:',
          err.message,
        );
      });

    return token.id;
  }

  // Hash user agent
  private async hashUserAgent(request: Request): Promise<string> {
    const userAgent = request.headers['user-agent']; // Get user agent
    return userAgent && (await this.bcryptService.hash(userAgent)); // Hash the user agent using bcrypt
  }

  // Find and verify refresh token by id
  private async getAndVerifyRefreshToken(
    id: string,
    res: Response,
  ): Promise<Token & { user: User }> {
    return this.prismaService.$transaction(async (tx) => {
      // Find refresh token in database
      const token = await tx.token.findUnique({
        where: { id },
        include: { user: true },
      });

      !token && this.clearRefreshTokenCookie(res, 'Invalid refresh token'); // Clear invalid refresh token from cookie

      // Check is the refresh token expired
      if (token.expiresAt < new Date()) {
        await tx.token.delete({ where: { id: token.id } }); // Delete expired refresh token from db
        this.clearRefreshTokenCookie(res, 'Refresh token expired'); // Clear expired cookie
      }

      return token;
    });
  }

  // Clear refresh token cookie & throw exception
  private clearRefreshTokenCookie(res: Response, message: string): void {
    res.clearCookie('refresh_token'); // Clear expired cookie
    throw new UnauthorizedException(message);
  }

  // Clear compromised refresh token from cookies and delete it from db
  private async clearCompromisedToken(
    response: Response,
    id: string,
  ): Promise<never> {
    response.clearCookie('refresh_token'); // Clear refresh token from cookie
    await this.prismaService.token.delete({ where: { id } }); // Delete compromised refresh token from db
    throw new UnauthorizedException(
      'Suspicious activity detected. Please sign-in again',
    );
  }
}
