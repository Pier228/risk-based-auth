import { Controller, Post, Body, Res, Req, Patch } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Throttle } from '@nestjs/throttler';
import { ApiTags } from '@nestjs/swagger';
import { SignUpSwaggerDocs } from './swagger/sign-up-doc.decorator';
import { SignInSwaggerDocs } from './swagger/sign-in-doc.decorator';
import { Response } from 'express';
import type RequestWithId from 'src/common/entities/IRequestWithId';
import { SignOutSwaggerDocs } from './swagger/sign-out-doc.decorator';
import SignInDTO from './dto/sign.in.dto';
import SignUpDTO from './dto/sign.up.dto';
import ChangePasswordDTO from './dto/change.password.dto';
import { ChangePasswordSwaggerDocs } from './swagger/change-password-doc.decorator';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @SignUpSwaggerDocs()
  @Throttle({ default: { limit: 12, ttl: 5 * 60 * 1000 } }) // 12 requests per 5 minutes
  @Post('sign-up')
  async create(@Body() credentials: SignUpDTO) {
    return this.authService.signUp(credentials);
  }

  @SignInSwaggerDocs()
  @Post('sign-in')
  @Throttle({ default: { limit: 6, ttl: 3 * 60 * 1000 } }) // 6 requests per 3 minutes
  async signIn(
    @Req() req: RequestWithId,
    @Body() credentials: SignInDTO,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.authService.signIn(credentials, response, req);
  }

  @SignOutSwaggerDocs()
  @Post('sign-out')
  async signOut(
    @Req() { signedCookies }: RequestWithId,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.authService.signOut(signedCookies, response);
  }

  @ChangePasswordSwaggerDocs()
  @Throttle({ default: { limit: 5, ttl: 5 * 60 * 1000 } }) // 5 requests per 5 minutes
  @Patch('change-password')
  async changePassword(
    @Req() req: RequestWithId,
    @Body() passwords: ChangePasswordDTO,
    @Res({ passthrough: true }) response: Response,
  ) {
    const currentAccessToken = req.signedCookies?.['access_token'];
    return this.authService.changePassword(
      req.id!,
      passwords,
      response,
      currentAccessToken,
    );
  }
}
