import { INestApplication, ValidationPipe } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Test } from '@nestjs/testing';
import cookieParser from 'cookie-parser';
import { AppModule } from 'src/app.module';
import request from 'supertest';
import * as cookieSignature from 'cookie-signature';
import { PrismaService } from 'src/prisma-database/prisma.service';
import { REFRESH_TOKEN_CONFIG } from 'src/common/globals';
import decodeSignedCookie from './utils/decodeSignedCookie';
import { ConfigService } from '@nestjs/config';
import { Cache } from 'cache-manager';
import { CACHE_MANAGER } from '@nestjs/cache-manager';

describe('Security Middleware (e2e)', () => {
  let app: INestApplication;
  let jwtService: JwtService;
  let prismaService: PrismaService;
  let cookieSecret: string;
  let cacheManager: Cache;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();
    const configService = app.get(ConfigService);
    cookieSecret = configService.getOrThrow('COOKIE_SECRET');

    app.useGlobalPipes(
      new ValidationPipe({ transform: true, whitelist: true }),
    );
    app.enableCors({
      origin: configService.get('CORS_ALLOWED_ORIGIN') || '*',
      methods: ['GET', 'POST', 'PATCH', 'DELETE'],
      credentials: true,
    });
    app.use(cookieParser(cookieSecret));

    cacheManager = moduleRef.get<Cache>(CACHE_MANAGER);
    prismaService = moduleRef.get<PrismaService>(PrismaService);
    jwtService = moduleRef.get<JwtService>(JwtService);
    await app.init();
  });

  const clearDB = async () => {
    await prismaService.trustedDevice.deleteMany();
    await prismaService.authLog.deleteMany();
    await prismaService.token.deleteMany();
    await prismaService.user.deleteMany();
  };

  afterAll(async () => {
    await clearDB();
    await app.close();
  });

  beforeEach(async () => await clearDB());

  describe('Invalid or Compromised Tokens', () => {
    it('should return 401 when no token is provided', async () => {
      const response = await request(app.getHttpServer())
        .get('/some-protected-route')
        .expect(401);

      expect(response.body).toEqual({
        error: 'Unauthorized',
        message: 'No valid token provided',
        statusCode: 401,
      });
      expect(response.headers['set-cookie']).toBeFalsy();
    });

    it('should return 401 when token has an invalid signature', async () => {
      const fakeToken = await jwtService.signAsync(
        { id: crypto.randomUUID() },
        { secret: 'wrong-fake-secret' },
      );
      const signedCookie = 's:' + cookieSignature.sign(fakeToken, cookieSecret);

      const response = await request(app.getHttpServer())
        .get('/some-protected-route')
        .set('Cookie', [`access_token=${signedCookie}`])
        .expect(401);

      expect(response.body).toEqual({
        error: 'Unauthorized',
        message: 'invalid signature',
        statusCode: 401,
      });
    });

    it('should return 401 when refresh token is expired', async () => {
      const user = await prismaService.user.create({
        data: { email: 'expired@gmail.com', password: 'password123' },
      });
      const refreshToken = await prismaService.token.create({
        data: {
          userId: user.id,
          expiresAt: new Date(Date.now() - 5000),
        },
      });

      const signedCookie =
        's:' + cookieSignature.sign(refreshToken.id, cookieSecret);

      const response = await request(app.getHttpServer())
        .get('/some-protected-route')
        .set('Cookie', [`refresh_token=${signedCookie}`])
        .expect(401);

      expect(response.body).toEqual({
        error: 'Unauthorized',
        message: 'Refresh token expired',
        statusCode: 401,
      });
    });

    it('should return 401 when access token is blacklisted', async () => {
      const accessToken = await jwtService.signAsync({
        id: crypto.randomUUID(),
      });
      const signedCookie =
        's:' + cookieSignature.sign(accessToken, cookieSecret);

      await cacheManager.set(
        accessToken,
        { blockedAt: Date.now(), reason: 'sign_out' },
        60000,
      );

      const response = await request(app.getHttpServer())
        .get('/some-protected-route')
        .set('Cookie', [`access_token=${signedCookie}`])
        .expect(401);

      expect(response.body).toEqual({
        error: 'Unauthorized',
        message:
          'This access token is blacklisted. Reason: sign_out. Please sign in again.',
        statusCode: 401,
      });
    });

    it('should return 401, clear cookies and delete refresh token if device is not trusted (2FA enabled)', async () => {
      const user = await prismaService.user.create({
        data: {
          email: 'device-binding@gmail.com',
          password: 'password123',
          twoFactorAuthEnabled: true,
          trustedDevices: {
            create: { visitorId: 'genuine-pc-id' },
          },
        },
      });

      const token = await prismaService.token.create({
        data: {
          userId: user.id,
          expiresAt: new Date(Date.now() + REFRESH_TOKEN_CONFIG.MAX_AGE),
        },
      });

      const signedCookie = 's:' + cookieSignature.sign(token.id, cookieSecret);

      const response = await request(app.getHttpServer())
        .get('/some-protected-route')
        .set('Cookie', [`refresh_token=${signedCookie}`])
        .set('x-visitor-id', 'attacker-hacker-pc') 
        .expect(401);

      expect(response.body).toEqual({
        error: 'Unauthorized',
        message: 'Suspicious activity detected. Please sign-in again',
        statusCode: 401,
      });

      const tokenInDb = await prismaService.token.findUnique({
        where: { id: token.id },
      });
      expect(tokenInDb).toBeNull();
    });
  });

  describe('Valid Tokens and Token Rotation', () => {
    it('should pass middleware when access token is valid (returns 404 for nonexistent route)', async () => {
      const accessToken = await jwtService.signAsync({
        id: crypto.randomUUID(),
      });
      const signedCookie =
        's:' + cookieSignature.sign(accessToken, cookieSecret);

      const response = await request(app.getHttpServer())
        .get('/some-nonexistent-route')
        .set('Cookie', [`access_token=${signedCookie}`])
        .expect(404);

      expect(response.body).toEqual({
        error: 'Not Found',
        message: 'Cannot GET /some-nonexistent-route',
        statusCode: 404,
      });
    });

    it('should rotate refresh token and issue new access token when refreshing session', async () => {
      const user = await prismaService.user.create({
        data: {
          email: 'rotate-ok@gmail.com',
          password: 'password123',
          twoFactorAuthEnabled: true,
          trustedDevices: {
            create: { visitorId: 'my-trusted-laptop' },
          },
        },
      });

      const oldRefreshToken = await prismaService.token.create({
        data: {
          userId: user.id,
          expiresAt: new Date(Date.now() + REFRESH_TOKEN_CONFIG.MAX_AGE),
        },
      });

      const signedCookie =
        's:' + cookieSignature.sign(oldRefreshToken.id, cookieSecret);

      const response = await request(app.getHttpServer())
        .get('/some-nonexistent-route')
        .set('Cookie', [`refresh_token=${signedCookie}`])
        .set('x-visitor-id', 'my-trusted-laptop')
        .expect(404);

      const newAccessToken = decodeSignedCookie(
        response.headers['set-cookie'][0],
        'access_token',
      );
      const newRefreshToken = decodeSignedCookie(
        response.headers['set-cookie'][1],
        'refresh_token',
      );

      expect(newAccessToken).toBeTruthy();
      expect(newRefreshToken).toBeTruthy();
      expect(newRefreshToken).not.toBe(oldRefreshToken.id);

      const oldTokenInDb = await prismaService.token.findUnique({
        where: { id: oldRefreshToken.id },
      });
      expect(oldTokenInDb).toBeNull();
    });
  });
});
