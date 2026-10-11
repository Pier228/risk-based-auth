import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { PrismaService } from 'src/prisma-database/prisma.service';
import { AppModule } from 'src/app.module';
import mockUsers from '../utils/mockData/users';
import { ThrottlerStorage } from '@nestjs/throttler';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import { ConfigService } from '@nestjs/config';
import { EmailSenderService } from 'src/shared/email-sender/email-sender.service';

describe('Auth Sign-Up (e2e)', () => {
  let app: INestApplication;
  let prismaService: PrismaService;
  
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

  describe('/auth/sign-up (POST)', () => {
    it('should create user, profile, confirmation record and return 201', async () => {
      const userPayload = mockUsers.validSignUpParams[0];

      const response = await request(app.getHttpServer())
        .post('/auth/sign-up')
        .send(userPayload)
        .expect(201);

      expect(response.body).toEqual({
        message:
          'User created successfully. Please confirm your email to activate your account.',
        confirmationId: expect.any(String),
      });

      const createdUser = await prismaService.user.findUnique({
        where: { email: userPayload.email },
        include: { Confirmation: true, Profile: true },
      });

      expect(createdUser).toBeTruthy();
      expect(createdUser?.emailConfirmed).toBe(false);
      expect(createdUser?.twoFactorAuthEnabled).toBe(false);
      expect(createdUser?.Profile?.name).toBe(userPayload.name);
      expect(createdUser?.Profile?.surname).toBe(userPayload.surname);
      expect(createdUser?.Confirmation).toHaveLength(1);
      expect(createdUser?.Confirmation[0].type).toBe('EMAIL_VERIFICATION');
    });

    it('should delete old unconfirmed user if previous confirmation expired and register anew', async () => {
      const oldUser = await prismaService.user.create({
        data: {
          email: 'retry-signup@gmail.com',
          password: 'oldpassword123',
          emailConfirmed: false,
          Confirmation: {
            create: {
              token: 'hashedtoken',
              type: 'EMAIL_VERIFICATION',
              expiresAt: new Date(Date.now() - 1000 * 60 * 60),
            },
          },
        },
      });

      const response = await request(app.getHttpServer())
        .post('/auth/sign-up')
        .send({
          email: 'retry-signup@gmail.com',
          password: 'newpassword123',
          name: 'Artem',
          surname: 'Dev',
        })
        .expect(201);

      expect(response.body.confirmationId).toBeTruthy();

      const newUser = await prismaService.user.findUnique({
        where: { email: 'retry-signup@gmail.com' },
      });

      expect(newUser).toBeTruthy();
      expect(newUser?.id).not.toBe(oldUser.id);
    });

    it('should return 400 on invalid signup body params', async () => {
      for (const invalidParams of mockUsers.signUpInvalidParams.slice(0, 3)) {
        const response = await request(app.getHttpServer())
          .post('/auth/sign-up')
          .send(invalidParams)
          .expect(400);

        expect(response.body.statusCode).toBe(400);
        expect(response.body.error).toBe('Bad Request');
      }
    });

    it('should return 409 Conflict if email is already registered and confirmed', async () => {
      await prismaService.user.create({
        data: {
          email: 'already-confirmed@gmail.com',
          password: 'password123',
          emailConfirmed: true,
        },
      });

      const response = await request(app.getHttpServer())
        .post('/auth/sign-up')
        .send({
          email: 'already-confirmed@gmail.com',
          password: 'newpassword123',
          name: 'John',
          surname: 'Doe',
        })
        .expect(409);

      expect(response.body).toEqual({
        statusCode: 409,
        error: 'Conflict',
        message: 'User with this email is already registered',
      });
    });

    it('should return 409 Conflict if confirmation was sent and is still active', async () => {
      await prismaService.user.create({
        data: {
          email: 'active-token@gmail.com',
          password: 'password123',
          emailConfirmed: false,
          Confirmation: {
            create: {
              token: 'active_hash',
              type: 'EMAIL_VERIFICATION',
              expiresAt: new Date(Date.now() + 1000 * 60 * 10),
            },
          },
        },
      });

      const response = await request(app.getHttpServer())
        .post('/auth/sign-up')
        .send({
          email: 'active-token@gmail.com',
          password: 'password123',
          name: 'John',
          surname: 'Doe',
        })
        .expect(409);

      expect(response.body).toEqual({
        statusCode: 409,
        error: 'Conflict',
        message: 'A confirmation letter has already been sent to this email',
      });
    });
  });
});
