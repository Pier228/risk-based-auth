import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { PrismaService } from 'src/prisma-database/prisma.service';
import * as bcrypt from 'bcrypt';
import { AppModule } from 'src/app.module';
import { ThrottlerStorage } from '@nestjs/throttler';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import decodeSignedCookie from '../utils/decodeSignedCookie';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as cookieSignature from 'cookie-signature';
import { Cache } from 'cache-manager';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { EmailSenderService } from 'src/shared/email-sender/email-sender.service';

describe('Auth Change-Password (e2e)', () => {
  let app: INestApplication;
  let prismaService: PrismaService;
  let jwtService: JwtService;
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
      .overrideProvider(EmailSenderService)
      .useValue({
        sendEmail: jest.fn().mockResolvedValue({
          message: 'Email has been sent',
          response: { Messages: [{ Status: 'success' }] },
        }),
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
    jwtService = moduleRef.get<JwtService>(JwtService);
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

  afterAll(async () => {
    await clearDB();
    await app.close();
  });

  beforeEach(async () => await clearDB());

  describe('/auth/change-password (PATCH)', () => {
    it('should return 401 when request is not authenticated', async () => {
      const response = await request(app.getHttpServer())
        .patch('/auth/change-password')
        .send({
          currentPassword: 'OldPassword123',
          newPassword: 'NewPassword123',
        })
        .expect(401);

      expect(response.body.message).toBe('No valid token provided');
    });

    it('should return 400 when currentPassword is wrong', async () => {
      const user = await prismaService.user.create({
        data: {
          email: 'changepwd1@gmail.com',
          password: bcrypt.hashSync('OldPassword123', saltRounds),
          emailConfirmed: true,
        },
      });

      const accessToken = await jwtService.signAsync({ id: user.id });
      const signedCookie =
        's:' + cookieSignature.sign(accessToken, cookieSecret);

      const response = await request(app.getHttpServer())
        .patch('/auth/change-password')
        .set('Cookie', [`access_token=${signedCookie}`])
        .send({
          currentPassword: 'WrongOldPassword123',
          newPassword: 'NewPassword123',
        })
        .expect(400);

      expect(response.body.message).toBe('Incorrect current password');
    });

    it('should return 400 when newPassword is same as currentPassword', async () => {
      const user = await prismaService.user.create({
        data: {
          email: 'changepwd2@gmail.com',
          password: bcrypt.hashSync('OldPassword123', saltRounds),
          emailConfirmed: true,
        },
      });

      const accessToken = await jwtService.signAsync({ id: user.id });
      const signedCookie =
        's:' + cookieSignature.sign(accessToken, cookieSecret);

      const response = await request(app.getHttpServer())
        .patch('/auth/change-password')
        .set('Cookie', [`access_token=${signedCookie}`])
        .send({
          currentPassword: 'OldPassword123',
          newPassword: 'OldPassword123',
        })
        .expect(400);

      expect(response.body.message).toBe(
        'New password must be different from current password',
      );
    });

    it('should return 200, update password, revoke old sessions, and issue fresh cookies', async () => {
      const user = await prismaService.user.create({
        data: {
          email: 'changepwd-success@gmail.com',
          password: bcrypt.hashSync('OldPassword123', saltRounds),
          emailConfirmed: true,
        },
      });

      // Створюємо 2 активні сесії (наприклад, з інших пристроїв)
      await prismaService.token.createMany({
        data: [
          { userId: user.id, expiresAt: new Date(Date.now() + 100000) },
          { userId: user.id, expiresAt: new Date(Date.now() + 100000) },
        ],
      });

      const oldAccessToken = await jwtService.signAsync({ id: user.id });
      const signedCookie =
        's:' + cookieSignature.sign(oldAccessToken, cookieSecret);

      const response = await request(app.getHttpServer())
        .patch('/auth/change-password')
        .set('Cookie', [`access_token=${signedCookie}`])
        .send({
          currentPassword: 'OldPassword123',
          newPassword: 'BrandNewPassword123',
        })
        .expect(200);

      expect(response.body).toEqual({
        message: 'Password has been successfully changed',
      });

      // 1. Пароль у базі оновився
      const updatedUser = await prismaService.user.findUnique({
        where: { id: user.id },
      });
      const isMatch = await bcrypt.compare(
        'BrandNewPassword123',
        updatedUser!.password,
      );
      expect(isMatch).toBe(true);

      // 2. Усі старі токени видалені, а створений лише 1 новий для поточної сесії
      const activeTokens = await prismaService.token.findMany({
        where: { userId: user.id },
      });
      expect(activeTokens).toHaveLength(1);

      // 3. Старий access_token занесено до blacklist у Redis
      const blacklisted = await cacheManager.get<{ reason: string }>(
        oldAccessToken,
      );
      expect(blacklisted?.reason).toBe('password_changed');

      // 4. Клієнту видано нові валідні cookies
      const newAccessCookie = decodeSignedCookie(
        response.headers['set-cookie'][0],
        'access_token',
      );
      const newRefreshCookie = decodeSignedCookie(
        response.headers['set-cookie'][1],
        'refresh_token',
      );
      expect(newAccessCookie).toBeTruthy();
      expect(newRefreshCookie).toBeTruthy();
    });
  });
});
