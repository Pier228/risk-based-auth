import {
  Inject,
  Injectable,
  NestMiddleware,
  UnauthorizedException,
} from '@nestjs/common';
import { Response, NextFunction } from 'express';
import { JwtService, TokenExpiredError } from '@nestjs/jwt';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import type RequestWithId from 'src/common/entities/IRequestWithId';
import { TokenService } from 'src/shared/token/token.service';

@Injectable()
export class SecurityMiddleware implements NestMiddleware {
  constructor(
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
    private readonly jwtService: JwtService,
    private readonly tokenService: TokenService,
  ) {}

  async use(req: RequestWithId, res: Response, next: NextFunction) {
    try {
      const access_token = req.signedCookies?.['access_token']; // Get the access token

      if (access_token) {
        const inBlackList = await this.cacheManager.get<Record<string, any>>(access_token);
        if (inBlackList) {
          res.clearCookie('access_token');
          throw new UnauthorizedException(
            `This access token is blacklisted. Reason: ${inBlackList?.reason || 'no provided'}. Please sign in again.`,
          );
        }

        try {
          const payload = await this.jwtService.verifyAsync(access_token); // Verify access token
          req.id = payload.id; // Set user id in request body
          return next();
        } catch (err: any) {
          if (err instanceof TokenExpiredError || err?.name === 'TokenExpiredError') {
            res.clearCookie('access_token');
            await this.tokenService.createAccessTokenUsingRefreshToken(req, res);
            return next();
          }
          throw err;
        }
      }

      await this.tokenService.createAccessTokenUsingRefreshToken(req, res);
      next();
    } catch (error: any) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException(error.message || 'Unauthorized');
    }
  }
}