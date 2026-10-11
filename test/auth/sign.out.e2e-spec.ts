import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { PrismaService } from 'src/prisma-database/prisma.service';
import * as bcrypt from 'bcrypt';
import { AppModule } from 'src/app.module';
import mockUsers from '../utils/mockData/users';
import { ThrottlerStorage } from '@nestjs/throttler';
import cookieParser from 'cookie-parser';
import request, { Response as SuperTestResponse } from 'supertest';
import decodeSignedCookie from '../utils/decodeSignedCookie';
import { ConfigService } from '@nestjs/config';
import { Cache } from 'cache-manager';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { BLACK_LIST_REASONS } from 'src/common/globals';

describe('Auth Sign-Out (e2e)', () => {
  let app: INestApplication;
  let prismaService: PrismaService;
  let cacheManager: Cache;
  let cookieSecret: string;
  let saltRounds: number;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(ThrottlerStorage)
      .useValue({
        increment: jest
          .fn()
          .mockResolvedValue({ totalHits: 0, timeToExpire: 0 }),
      })
      .compile();

    app = moduleRef.createNestApplication();
    const configService = app.get(ConfigService);
    cookieSecret = configService.getOrThrow('COOKIE_SECRET');
    saltRounds = Number(configService.get('SALT_ROUNDS')) || 12;

    app.useGlobalPipes(
      new ValidationPipe({ transform: true, whitelist: true }),
    );
    app.enableCors({
      origin: configService.get('CORS_ALLOWED_ORIGIN') || '*',
      methods: ['GET', 'POST', 'PATCH', 'DELETE'],
      credentials: true,
    });
    app.use(cookieParser(cookieSecret));

    prismaService = moduleRef.get<PrismaService>(PrismaService);
    cacheManager = moduleRef.get<Cache>(CACHE_MANAGER);
    await app.init();
  });

  const clearDB = async () => {
    await prismaService.trustedDevice.deleteMany();
    await prismaService.authLog.deleteMany();
    await prismaService.confirmation.deleteMany();
    await prismaService.token.deleteMany();
    await prismaService.profile.deleteMany();
    await prismaService.user.deleteMany();
  };

  const getCookies = (res: SuperTestResponse): string[] => {
    const raw = res.headers['set-cookie'];
    if (!raw) return [];
    return Array.isArray(raw) ? raw : [raw];
  };

  afterAll(async () => {
    await clearDB();
    await app.close();
  });

  beforeEach(async () => await clearDB());

  describe('/auth/sign-out (POST)', () => {
    it('should return 201, clear access_token cookie and add token to Redis blacklist', async () => {
      const { email, password } = mockUsers.validSignUpParams[0];
      await prismaService.user.create({
        data: {
          email,
          password: bcrypt.hashSync(password, saltRounds),
          emailConfirmed: true,
        },
      });

      const signInRes = await request(app.getHttpServer())
        .post('/auth/sign-in')
        .send({ email, password })
        .expect(201);

      const cookies = getCookies(signInRes);
      const accessCookie = cookies.find((c) => c.startsWith('access_token='));
      expect(accessCookie).toBeTruthy();

      const rawAccessToken = decodeSignedCookie(accessCookie!, 'access_token');
      expect(rawAccessToken).toBeTruthy();

      const response = await request(app.getHttpServer())
        .post('/auth/sign-out')
        .set('Cookie', [accessCookie!])
        .expect(201);

      expect(response.body).toEqual({
        message: 'Successfully signed out',
      });

      const responseCookies = getCookies(response);
      const clearedCookie = decodeSignedCookie(
        responseCookies[0],
        'access_token',
      );
      expect(clearedCookie).toBeFalsy();

      const blacklisted = await cacheManager.get<{ reason: string }>(
        rawAccessToken as string,
      );
      expect(blacklisted).toBeTruthy();
      expect(blacklisted?.reason).toBe(BLACK_LIST_REASONS.SIGN_OUT);
    });

    it('should return 201, clear refresh_token cookie and remove it from DB', async () => {
      const { email, password } = mockUsers.validSignUpParams[0];
      await prismaService.user.create({
        data: {
          email,
          password: bcrypt.hashSync(password, saltRounds),
          emailConfirmed: true,
        },
      });

      const signInRes = await request(app.getHttpServer())
        .post('/auth/sign-in')
        .send({ email, password })
        .expect(201);

      const cookies = getCookies(signInRes);
      const refreshCookie = cookies.find((c) => c.startsWith('refresh_token='));
      expect(refreshCookie).toBeTruthy();

      const rawRefreshToken = decodeSignedCookie(
        refreshCookie!,
        'refresh_token',
      );
      expect(rawRefreshToken).toBeTruthy();

      const response = await request(app.getHttpServer())
        .post('/auth/sign-out')
        .set('Cookie', [refreshCookie!])
        .expect(201);

      expect(response.body).toEqual({
        message: 'Successfully signed out',
      });

      const tokenInDb = await prismaService.token.findUnique({
        where: { id: rawRefreshToken as string },
      });
      expect(tokenInDb).toBeNull();
    });

    it('should return 201 and clear both tokens simultaneously', async () => {
      const { email, password } = mockUsers.validSignUpParams[0];
      await prismaService.user.create({
        data: {
          email,
          password: bcrypt.hashSync(password, saltRounds),
          emailConfirmed: true,
        },
      });

      const signInRes = await request(app.getHttpServer())
        .post('/auth/sign-in')
        .send({ email, password })
        .expect(201);

      const cookies = getCookies(signInRes);

      const response = await request(app.getHttpServer())
        .post('/auth/sign-out')
        .set('Cookie', cookies)
        .expect(201);

      expect(response.body).toEqual({
        message: 'Successfully signed out',
      });

      const cookiesOut = getCookies(response);
      expect(decodeSignedCookie(cookiesOut[0], 'refresh_token')).toBeFalsy();
      expect(decodeSignedCookie(cookiesOut[1], 'access_token')).toBeFalsy();
    });
  });
});
