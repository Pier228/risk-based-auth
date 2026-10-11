import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { PrismaService } from 'src/prisma-database/prisma.service';
import { AppModule } from 'src/app.module';
import { ThrottlerStorage } from '@nestjs/throttler';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import { CONFIRMATION_CONFIG } from 'src/common/globals';
import { ConfigService } from '@nestjs/config';
import { BcryptService } from 'src/shared/bcrypt/bcrypt.service';
import { EmailSenderService } from 'src/shared/email-sender/email-sender.service';

describe('Confirmation Resend (e2e)', () => {
  let app: INestApplication;
  let prismaService: PrismaService;
  let bcryptService: BcryptService;

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
    bcryptService = moduleRef.get<BcryptService>(BcryptService);
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

  describe('/confirmation/resend (POST)', () => {
    it('should return 400 on invalid confirmationId UUID format', async () => {
      const invalidIds = ['123', 'invalid-uuid-string', ''];
      for (const confirmationId of invalidIds) {
        const response = await request(app.getHttpServer())
          .post('/confirmation/resend')
          .send({ confirmationId })
          .expect(400);

        expect(response.body.statusCode).toBe(400);
        expect(response.body.error).toBe('Bad Request');
      }
    });

    it('should return 404 if confirmation record does not exist', async () => {
      const response = await request(app.getHttpServer())
        .post('/confirmation/resend')
        .send({ confirmationId: crypto.randomUUID() })
        .expect(404);

      expect(response.body).toEqual({
        statusCode: 404,
        error: 'Not Found',
        message: 'Confirmation record not found',
      });
    });

    it('should return 400 if resend threshold has not passed yet (Rate Limit by time)', async () => {
      const user = await prismaService.user.create({
        data: {
          email: 'spam-protection@gmail.com',
          password: 'password123',
          Profile: {
            create: { name: 'Alex', surname: 'Smith' },
          },
        },
      });

      const confirmation = await prismaService.confirmation.create({
        data: {
          userId: user.id,
          token: await bcryptService.hash('123456'),
          type: 'EMAIL_VERIFICATION',
          expiresAt: new Date(
            Date.now() + CONFIRMATION_CONFIG.VERIFICATION_TIME,
          ),
          createdAt: new Date(),
        },
      });

      const response = await request(app.getHttpServer())
        .post('/confirmation/resend')
        .send({ confirmationId: confirmation.id })
        .expect(400);

      expect(response.body).toEqual({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Please wait a bit before requesting again.',
        secondsRemaining: expect.any(Number),
        minutesRemaining: expect.any(Number),
        retryAt: expect.any(String),
      });
    });

    it('should return 201, delete old confirmation and issue a new one when threshold has passed', async () => {
      const user = await prismaService.user.create({
        data: {
          email: 'resend-allowed@gmail.com',
          password: 'password123',
          Profile: {
            create: { name: 'Artem', surname: 'Bukhanenko' },
          },
        },
      });

      const oldConfirmation = await prismaService.confirmation.create({
        data: {
          userId: user.id,
          token: await bcryptService.hash('111222'),
          type: 'EMAIL_VERIFICATION',
          expiresAt: new Date(Date.now() + 1000 * 60 * 10),
          createdAt: new Date(
            Date.now() - (CONFIRMATION_CONFIG.RESEND_THRESHOLD + 10000),
          ),
        },
      });

      const response = await request(app.getHttpServer())
        .post('/confirmation/resend')
        .send({ confirmationId: oldConfirmation.id })
        .expect(201);

      expect(response.body).toEqual({
        message: 'Confirmation letter has been successfully sent',
        confirmationId: expect.any(String),
      });
      expect(response.body.confirmationId).not.toBe(oldConfirmation.id);

      const oldCheck = await prismaService.confirmation.findUnique({
        where: { id: oldConfirmation.id },
      });
      const newCheck = await prismaService.confirmation.findUnique({
        where: { id: response.body.confirmationId },
      });

      expect(oldCheck).toBeNull();
      expect(newCheck).toBeTruthy();
    });
  });
});
