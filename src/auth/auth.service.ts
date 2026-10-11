import {
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma-database/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { Response } from 'express';
import { BLACK_LIST_REASONS, LETTER_TEMPLATES } from 'src/common/globals';
import { ConfirmationService } from 'src/confirmation/confirmation.service';
import SignInDTO from './dto/sign.in.dto';
import SignUpDTO from './dto/sign.up.dto';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { SecurityService } from 'src/security/security.service';
import { User } from 'generated/prisma';
import { BcryptService } from 'src/shared/bcrypt/bcrypt.service';
import { TokenService } from 'src/shared/token/token.service';
import type RequestWithId from 'src/common/entities/IRequestWithId';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly confirmationService: ConfirmationService,
    private readonly tokenService: TokenService,
    private readonly securityService: SecurityService,
    private readonly bcryptService: BcryptService,
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
  ) {}

  // Sign up user & create user, profile, confirmation record in DB & send email confirmation letter
  async signUp(credentials: SignUpDTO): Promise<Record<string, string>> {
    await this.isRegistrationAllowed(credentials.email); // Check is the registration allowed for this email address

    const hashedPassword = await this.bcryptService.hash(credentials.password); // Hash the password using bcrypt

    const confirmationId = await this.registerUser({
      ...credentials,
      password: hashedPassword,
    }); // Create new user, profile, email confirmation in the database & Send email confirmation letter

    return {
      message:
        'User created successfully. Please confirm your email to activate your account.',
      confirmationId,
    };
  }

  // Sign in user's account & set up auth cookies
  async signIn(
    { email, password }: SignInDTO,
    response: Response,
    request: RequestWithId,
  ) {
    const user = await this.prisma.user.findUnique({ where: { email } }); // Find user by email

    // Check if user exists and password matches
    if (!user || !(await this.bcryptService.compare(password, user.password))) {
      if (user) {
        await this.securityService.recordFailedLoginAttempt(user.id);
      }
      throw new UnauthorizedException('Wrong email or password');
    }

    // Check if the users email is confirmed.
    if (!user.emailConfirmed) {
      throw new ForbiddenException('Email address is not confirmed');
    }

    // Two factor auth
    if (user.twoFactorAuthEnabled) {
      await this.twoFactorAuthSecurity(user, request);
    }

    // Successful sign-in without 2FA (or after completing it) resets the failed attempt counter
    await this.securityService.clearFailedLoginAttempts(user.id);

    await this.tokenService.setAuthCookies(user, response); // Create and set auth cookies
    return { message: 'User successfully logged in' };
  }

  // Sign out from user's account & clear auth cookies
  async signOut(
    { refresh_token, access_token }: Record<string, any>,
    response: Response,
  ): Promise<{ message: string }> {
    if (refresh_token) {
      const token = await this.prisma.token.findUnique({
        where: { id: refresh_token },
      });

      // Delete the refresh token from db
      token &&
        (await this.prisma.token.delete({ where: { id: refresh_token } }));

      response.clearCookie('refresh_token'); // Clear refresh token cookie
    }

    if (access_token) {
      const { exp } = this.jwtService.decode(access_token);
      const ttl = exp * 1000 - Date.now(); // Calculate the remaining time until the access token expires, in milliseconds

      // Add access token to block list
      await this.cacheManager.set(
        access_token,
        {
          blockedAt: Date.now(),
          reason: BLACK_LIST_REASONS.SIGN_OUT,
        },
        ttl,
      );

      response.clearCookie('access_token'); // Clear access token cookie
    }

    return { message: 'Successfully signed out' };
  }

  // Check is the registration allowed for this email address
  private async isRegistrationAllowed(email: string): Promise<void> {
    const existingUser = await this.prisma.user.findUnique({
      where: { email },
      include: {
        Confirmation: {
          where: { type: 'EMAIL_VERIFICATION' },
          select: { expiresAt: true },
        },
      },
    });

    const now = new Date();
    const confirmation = existingUser?.Confirmation?.[0];
    const isTokenExpired = confirmation && confirmation.expiresAt < now;
    const isTokenActive = confirmation && confirmation.expiresAt > now;

    if (existingUser?.emailConfirmed) {
      throw new ConflictException('User with this email is already registered');
    }

    if (existingUser && !existingUser.emailConfirmed) {
      if (!confirmation || isTokenExpired) {
        await this.prisma.user.delete({ where: { email: email } });
      } else if (isTokenActive) {
        throw new ConflictException(
          'A confirmation letter has already been sent to this email',
        );
      }
    }
  }

  // Create new user, profile, email confirmation in the database & Send email confirmation letter
  private async registerUser({
    email,
    password,
    surname,
    name,
  }: SignUpDTO): Promise<string> {
    return this.prisma.$transaction(async (tx) => {
      // Create user
      const { id } = await tx.user.create({
        data: { email, password },
      });

      // Create profile
      await tx.profile.create({
        data: { name, surname, userId: id },
      });

      const customerName = name + ' ' + surname;

      // Create new confirmation & send confirmation email
      return this.confirmationService.createAndSendConfirmation({
        userId: id,
        email,
        customerName,
        type: 'EMAIL_VERIFICATION',
        tx,
        subject: LETTER_TEMPLATES.EMAIL_VERIFICATION.subject,
        TemplateID: LETTER_TEMPLATES.EMAIL_VERIFICATION.id,
      });
    });
  }

  // Verify user's authorization via 2FA, if failed -> throw exception
  private async twoFactorAuthSecurity(
    user: User,
    request: RequestWithId,
  ): Promise<void> {
    const result = await this.securityService.twoFactorAuth(user, request);

    if (result !== true) {
      throw new UnauthorizedException({
        message: result.message,
        confirmationId: result.confirmationId,
        statusCode: 401,
        error: 'Unauthorized',
      });
    }
  }
}
