import { INestApplication, ValidationPipe } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Test } from '@nestjs/testing';
import * as cookieParser from 'cookie-parser';
import { AppModule } from 'src/app.module';
import * as request from 'supertest';
import * as cookieSignature from 'cookie-signature';
import { PrismaService } from 'src/prisma-database/prisma.service';
import { REFRESH_TOKEN_CONFIG } from 'src/common/globals';
import decodeSignedCookie from './utils/decodeSignedCookie';
import { ConfigService } from '@nestjs/config';
import { BcryptService } from 'src/shared/bcrypt/bcrypt.service';
import { BcryptModule } from 'src/shared/bcrypt/bcrypt.module';
import { Cache } from 'cache-manager';
import { CACHE_MANAGER } from '@nestjs/cache-manager';

describe('Security Middleware (e2e)', () => {
  let app: INestApplication;
  let jwtService: JwtService;
  let prismaService: PrismaService;
  let cookieSecret: string;
  let cacheManager: Cache;
  let bcryptService: BcryptService;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule, BcryptModule],
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
    bcryptService = moduleRef.get<BcryptService>(BcryptService);
    prismaService = moduleRef.get<PrismaService>(PrismaService);
    jwtService = moduleRef.get<JwtService>(JwtService);
    await app.init();
  });

  const clearDB = async () => {
    await prismaService.user.deleteMany();
    await prismaService.token.deleteMany();
  };

  afterAll(async () => {
    await clearDB();
    await app.close();
  });

  beforeEach(async () => await clearDB());

  describe('Invalid tokens', () => {
    it('should return code 401 & No valid token provided', async () => {
      const response = await request(app.getHttpServer())
        .get('/some-route')
        .expect(401);

      expect(response.body).toEqual({
        error: 'Unauthorized',
        message: 'No valid token provided',
        statusCode: 401,
      });

      expect(response.headers['set-cookie']).toBeFalsy();
    });

    it('should return code 401 & invalid signature', async () => {
      const fakeToken = await jwtService.signAsync(
        { id: crypto.randomUUID() },
        { secret: 'fake' },
      );

      const signedCookie = 's:' + cookieSignature.sign(fakeToken, cookieSecret);

      const response = await request(app.getHttpServer())
        .get('/some-route')
        .set('Cookie', [`access_token=${signedCookie}`])
        .expect(401);

      expect(response.body).toEqual({
        error: 'Unauthorized',
        message: 'invalid signature',
        statusCode: 401,
      });

      expect(response.headers['set-cookie']).toBeFalsy();
    });

    it('should return code 401 & Invalid refresh token', async () => {
      const signedCookie =
        's:' + cookieSignature.sign(crypto.randomUUID(), cookieSecret);

      const response = await request(app.getHttpServer())
        .get('/some-route')
        .set('Cookie', [`refresh_token=${signedCookie}`])
        .expect(401);

      expect(response.body).toEqual({
        error: 'Unauthorized',
        message: 'Invalid refresh token',
        statusCode: 401,
      });

      const refreshToken = decodeSignedCookie(
        response.headers['set-cookie'][0],
        'refresh_token',
      );

      expect(refreshToken).toBeFalsy();
    });

    it('should return code 401 & Refresh token expired', async () => {
      const refreshToken = await prismaService.$transaction(async (tx) => {
        const { id } = await tx.user.create({
          data: { email: 'example@gmail.com', password: 'asfasfasfsaf' },
        });

        const refreshToken = await tx.token.create({
          data: {
            userId: id,
            expiresAt: new Date(Date.now() - 5000),
          },
        });

        return refreshToken;
      });

      const signedCookie =
        's:' + cookieSignature.sign(refreshToken.id, cookieSecret);

      const response = await request(app.getHttpServer())
        .get('/some-route')
        .set('Cookie', [`refresh_token=${signedCookie}`])
        .expect(401);

      expect(response.body).toEqual({
        error: 'Unauthorized',
        message: 'Refresh token expired',
        statusCode: 401,
      });

      const unsignedRefreshToken = decodeSignedCookie(
        response.headers['set-cookie'][0],
        'refresh_token',
      );

      expect(unsignedRefreshToken).toBeFalsy();
    });

    it('should return code 401 & Access token is in blacklist', async () => {
      const accessToken = await jwtService.signAsync({
        id: crypto.randomUUID(),
      });

      const signedCookie =
        's:' + cookieSignature.sign(accessToken, cookieSecret);

      await cacheManager.set(
        accessToken,
        {
          blockedAt: Date.now(),
        },
        1 * 60 * 1000,
      );

      const response = await request(app.getHttpServer())
        .get('/some-route')
        .set('Cookie', [`access_token=${signedCookie}`])
        .expect(401);

      expect(response.body).toEqual({
        error: 'Unauthorized',
        message:
          'This access token is blacklisted. Reason: no provided. Please sign in again.',
        statusCode: 401,
      });

      const unsignedAccessToken = decodeSignedCookie(
        response.headers['set-cookie'][0],
        'access_token',
      );

      expect(unsignedAccessToken).toBeFalsy();
    });

    it('should return code 401 & Unauthorized exception', async () => {
      const tokenId = await prismaService.$transaction(async (tx) => {
        const user = await tx.user.create({
          data: {
            email: `${Date.now()}@gmail.com`,
            password: Date.now().toString(),
            emailConfirmed: true,
            twoFactorAuthEnabled: true,
          },
        });

        const token = await tx.token.create({
          data: {
            userId: user.id,
            expiresAt: new Date(Date.now() + REFRESH_TOKEN_CONFIG.MAX_AGE),
            twoFactorUserAgent: 'Wrong User Agent',
          },
        });

        return token.id;
      });

      const signedCookie = 's:' + cookieSignature.sign(tokenId, cookieSecret);

      const response = await request(app.getHttpServer())
        .get('/some-route')
        .set('Cookie', [`refresh_token=${signedCookie}`])
        .set('User-Agent', 'Chrome 1.2.3')
        .expect(401);

      expect(response.body).toEqual({
        error: 'Unauthorized',
        message: 'Suspicious activity detected. Please sign-in again',
        statusCode: 401,
      });

      const unsignedAccessToken = decodeSignedCookie(
        response.headers['set-cookie'][0],
        'refresh_token',
      );
      const token = await prismaService.token.findUnique({
        where: { id: tokenId },
      });

      expect(unsignedAccessToken).toBeFalsy();
      expect(token).toBeFalsy();
    });
  });

  describe('Valid tokens', () => {
    it('should return code 404 & Route not found (Access token verified successfully)', async () => {
      const accessToken = await jwtService.signAsync({
        id: crypto.randomUUID(),
      });

      const signedCookie =
        's:' + cookieSignature.sign(accessToken, cookieSecret);

      const response = await request(app.getHttpServer())
        .get('/some-route')
        .set('Cookie', [`access_token=${signedCookie}`])
        .expect(404);

      expect(response.body).toEqual({
        error: 'Not Found',
        message: 'Cannot GET /some-route',
        statusCode: 404,
      });
    });
  });

  it('should return code 404 & Route not found (Refresh token verified successfully & returned new access token)', async () => {
    const refreshToken = await prismaService.$transaction(async (tx) => {
      const { id } = await tx.user.create({
        data: { email: 'test@gmail.com', password: 'asfasfasfsaf' },
      });

      const refreshToken = await tx.token.create({
        data: {
          userId: id,
          expiresAt: new Date(Date.now() + REFRESH_TOKEN_CONFIG.MAX_AGE),
        },
      });

      return refreshToken;
    });

    const signedCookie =
      's:' + cookieSignature.sign(refreshToken.id, cookieSecret);

    const response = await request(app.getHttpServer())
      .get('/some-route')
      .set('Cookie', [`refresh_token=${signedCookie}`])
      .expect(404);

    expect(response.body).toEqual({
      error: 'Not Found',
      message: 'Cannot GET /some-route',
      statusCode: 404,
    });

    const accessToken = decodeSignedCookie(
      response.headers['set-cookie'][0],
      'access_token',
    );

    expect(accessToken).toBeTruthy();
    const payload = await jwtService.verifyAsync(accessToken as string);
    expect(payload).toHaveProperty('id');
    expect(payload.id).toHaveLength(36);
  });

  it('should return code 404. Refresh token & User Agent verified successfully & returned new access token', async () => {
    const refreshToken = await prismaService.$transaction(async (tx) => {
      const { id } = await tx.user.create({
        data: {
          email: 'tes312t@gmail.com',
          password: 'asfasfasfsaf',
          twoFactorAuthEnabled: true,
        },
      });

      const refreshToken = await tx.token.create({
        data: {
          userId: id,
          expiresAt: new Date(Date.now() + REFRESH_TOKEN_CONFIG.MAX_AGE),
          twoFactorUserAgent: await bcryptService.hash('Chrome 1.2.3'),
        },
      });

      return refreshToken;
    });

    const signedCookie =
      's:' + cookieSignature.sign(refreshToken.id, cookieSecret);

    const response = await request(app.getHttpServer())
      .get('/some-route')
      .set('Cookie', [`refresh_token=${signedCookie}`])
      .set('User-Agent', 'Chrome 1.2.3')
      .expect(404);

    expect(response.body).toEqual({
      error: 'Not Found',
      message: 'Cannot GET /some-route',
      statusCode: 404,
    });

    const accessToken = decodeSignedCookie(
      response.headers['set-cookie'][0],
      'access_token',
    );

    expect(accessToken).toBeTruthy();
    const payload = await jwtService.verifyAsync(accessToken as string);
    expect(payload).toHaveProperty('id');
    expect(payload.id).toHaveLength(36);
  });
});
