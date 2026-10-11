import request from 'supertest';
import { Test } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { PrismaService } from 'src/prisma-database/prisma.service';
import * as bcrypt from 'bcrypt';
import { AppModule } from 'src/app.module';
import { JwtService } from '@nestjs/jwt';
import { ThrottlerStorage } from '@nestjs/throttler';
import cookieParser from 'cookie-parser';
import decodeSignedCookie from '../utils/decodeSignedCookie';
import { ConfigService } from '@nestjs/config';
import { EmailSenderService } from 'src/shared/email-sender/email-sender.service';

describe('Auth Controller (e2e)', () => {
  let app: INestApplication;
  let prismaService: PrismaService;
  let jwtService: JwtService;
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
    saltRounds = Number(configService.get('SALT_ROUNDS')) || 12;

    app.useGlobalPipes(
      new ValidationPipe({ transform: true, whitelist: true }),
    );
    app.enableCors({
      origin: configService.get('CORS_ALLOWED_ORIGIN') || '*',
      methods: ['GET', 'POST', 'PATCH', 'DELETE'],
      credentials: true,
    });
    app.use(cookieParser(configService.getOrThrow('COOKIE_SECRET')));

    prismaService = moduleRef.get<PrismaService>(PrismaService);
    jwtService = moduleRef.get<JwtService>(JwtService);
    await app.init();
  });

  const clearDB = async () => {
    await prismaService.trustedDevice.deleteMany();
    await prismaService.authLog.deleteMany();
    await prismaService.confirmation.deleteMany();
    await prismaService.token.deleteMany();
    await prismaService.user.deleteMany();
  };

  afterAll(async () => {
    await clearDB();
    await app.close();
  });

  beforeEach(async () => await clearDB());

  describe('/auth/sign-in (POST)', () => {
    it('should return 400 on invalid payload', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/sign-in')
        .send({ email: 'not-an-email', password: '' })
        .expect(400);

      expect(response.body.statusCode).toBe(400);
      expect(response.headers['set-cookie']).toBeFalsy();
    });

    it('should return 401 when user is not found', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/sign-in')
        .send({ email: 'unknown@gmail.com', password: 'password123' })
        .expect(401);

      expect(response.body).toEqual({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Wrong email or password',
      });
    });

    it('should return 401 on wrong password', async () => {
      const user = await prismaService.user.create({
        data: {
          email: 'valid@gmail.com',
          password: bcrypt.hashSync('correctPassword', saltRounds),
          emailConfirmed: true,
        },
      });

      const response = await request(app.getHttpServer())
        .post('/auth/sign-in')
        .send({ email: user.email, password: 'wrongPassword' })
        .expect(401);

      expect(response.body.message).toBe('Wrong email or password');
    });

    it('should return 403 when email is not confirmed', async () => {
      const user = await prismaService.user.create({
        data: {
          email: 'unconfirmed@gmail.com',
          password: bcrypt.hashSync('correctPassword', saltRounds),
          emailConfirmed: false,
        },
      });

      const response = await request(app.getHttpServer())
        .post('/auth/sign-in')
        .send({ email: user.email, password: 'correctPassword' })
        .expect(403);

      expect(response.body).toEqual({
        statusCode: 403,
        error: 'Forbidden',
        message: 'Email address is not confirmed',
      });
    });

    it('should return 201 and set auth cookies when 2FA is disabled', async () => {
      const user = await prismaService.user.create({
        data: {
          email: 'regular-login@gmail.com',
          password: bcrypt.hashSync('correctPassword', saltRounds),
          emailConfirmed: true,
          twoFactorAuthEnabled: false,
        },
      });

      const response = await request(app.getHttpServer())
        .post('/auth/sign-in')
        .send({ email: user.email, password: 'correctPassword' })
        .expect(201);

      expect(response.body).toEqual({ message: 'User successfully logged in' });

      const accessToken = decodeSignedCookie(
        response.headers['set-cookie'][0],
        'access_token',
      );
      const refreshToken = decodeSignedCookie(
        response.headers['set-cookie'][1],
        'refresh_token',
      );

      expect(accessToken).toBeTruthy();
      expect(refreshToken).toBeTruthy();
    });

    it('RBA: should return 401 & trigger 2FA OTP when device is unknown (Risk Score >= 30)', async () => {
      const user = await prismaService.user.create({
        data: {
          email: 'rba-stepup@gmail.com',
          password: bcrypt.hashSync('password123', saltRounds),
          emailConfirmed: true,
          twoFactorAuthEnabled: true,
          trustedDevices: {
            create: { visitorId: 'registered-laptop-1' },
          },
        },
      });

      const response = await request(app.getHttpServer())
        .post('/auth/sign-in')
        .set('x-visitor-id', 'unknown-external-device')
        .send({ email: user.email, password: 'password123' })
        .expect(401);

      expect(response.body).toEqual({
        statusCode: 401,
        error: 'Unauthorized',
        message:
          'Suspicious activity detected. A verification code has been sent to your email. Please check your inbox and enter the code to proceed',
        confirmationId: expect.any(String),
      });

      const confirmation = await prismaService.confirmation.findUnique({
        where: { id: response.body.confirmationId },
      });
      expect(confirmation?.type).toBe('TWO_FACTOR_AUTH');
    });

    it('RBA: should return 201 & seamlessly sign in without 2FA when device is trusted (Risk Score <= 29)', async () => {
      const user = await prismaService.user.create({
        data: {
          email: 'rba-seamless@gmail.com',
          password: bcrypt.hashSync('password123', saltRounds),
          emailConfirmed: true,
          twoFactorAuthEnabled: true,
          trustedDevices: {
            create: { visitorId: 'trusted-home-desktop' },
          },
        },
      });

      const response = await request(app.getHttpServer())
        .post('/auth/sign-in')
        .set('x-visitor-id', 'trusted-home-desktop')
        .send({ email: user.email, password: 'password123' })
        .expect(201);

      expect(response.body).toEqual({ message: 'User successfully logged in' });

      const accessToken = decodeSignedCookie(
        response.headers['set-cookie'][0],
        'access_token',
      );
      expect(accessToken).toBeTruthy();
    });

    it('RBA: should trigger 2FA on trusted device if failed login attempts burst detected', async () => {
      const user = await prismaService.user.create({
        data: {
          email: 'burst-attempts@gmail.com',
          password: bcrypt.hashSync('correctPassword', saltRounds),
          emailConfirmed: true,
          twoFactorAuthEnabled: true,
          trustedDevices: {
            create: { visitorId: 'trusted-device-burst' },
          },
        },
      });

      for (let i = 0; i < 3; i++) {
        await request(app.getHttpServer())
          .post('/auth/sign-in')
          .set('x-visitor-id', 'trusted-device-burst')
          .send({ email: user.email, password: 'wrongPassword' })
          .expect(401);
      }

      const response = await request(app.getHttpServer())
        .post('/auth/sign-in')
        .set('x-visitor-id', 'trusted-device-burst')
        .send({ email: user.email, password: 'correctPassword' })
        .expect(401);

      expect(response.body).toEqual({
        statusCode: 401,
        error: 'Unauthorized',
        message:
          'Suspicious activity detected. A verification code has been sent to your email. Please check your inbox and enter the code to proceed',
        confirmationId: expect.any(String),
      });
    });
  });
});
