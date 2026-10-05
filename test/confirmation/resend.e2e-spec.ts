import * as request from 'supertest';
import { Test } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { PrismaService } from 'src/prisma-database/prisma.service';
import { AppModule } from 'src/app.module';
import { ThrottlerStorage } from '@nestjs/throttler';
import * as cookieParser from 'cookie-parser';
import { CONFIRMATION_CONFIG } from 'src/common/globals';
import { ConfigService } from '@nestjs/config';
import { BcryptService } from 'src/shared/bcrypt/bcrypt.service';
import { BcryptModule } from 'src/shared/bcrypt/bcrypt.module';

describe('Confirmation Controller (e2e)', () => {
  let app: INestApplication;
  let prismaService: PrismaService;
  let bcryptService: BcryptService;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule, BcryptModule],
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
    await prismaService.user.deleteMany();
    await prismaService.confirmation.deleteMany();
  };

  afterAll(async () => {
    await clearDB();
    await app.close();
  });

  beforeEach(async () => await clearDB());

  describe('/confirmation/resend (POST)', () => {
    it('should return code 400 & validation error', async () => {
      const invalidData = [
        { confirmationId: '123213' },
        { confirmationId: 12312312 },
        { confirmationId: '' },
      ];

      for (const data of invalidData) {
        const response = await request(app.getHttpServer())
          .post('/confirmation/resend')
          .send(data)
          .expect(400);

        expect(response.body).toEqual({
          statusCode: 400,
          error: 'Bad Request',
          message: expect.any(Array || String),
        });
      }
    });

    it('should return http code 404 & NotFoundException', async () => {
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

    it('should return http code 400 & BadRequestException (not enough time has passed)', async () => {
      const { id } = await prismaService.$transaction(async (tx) => {
        const user = await tx.user.create({
          data: {
            email: Date.now() + '@gmail.com',
            password: Date.now().toString(),
          },
        });

        const { id } = await tx.confirmation.create({
          data: {
            userId: user.id,
            token: await bcryptService.hash('123321'),
            expiresAt: new Date(
              Date.now() + CONFIRMATION_CONFIG.VERIFICATION_TIME,
            ),
            type: 'EMAIL_VERIFICATION',
          },
        });

        return { id };
      });

      const response = await request(app.getHttpServer())
        .post('/confirmation/resend')
        .send({ confirmationId: id })
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

    it('should return http code 201 & confirmation letter has been resend', async () => {
      const token = '543765';
      const { id, user } = await prismaService.$transaction(async (tx) => {
        const user = await tx.user.create({
          data: {
            email: Date.now() + '@gmail.com',
            password: Date.now().toString(),
          },
        });

        await tx.profile.create({
          data: {
            name: Date.now().toString(),
            surname: Date.now().toString(),
            userId: user.id,
          },
        });

        const { id } = await tx.confirmation.create({
          data: {
            userId: user.id,
            token: await bcryptService.hash(token),
            expiresAt: new Date(
              Date.now() - CONFIRMATION_CONFIG.VERIFICATION_TIME,
            ),
            createdAt: new Date(
              Date.now() - CONFIRMATION_CONFIG.VERIFICATION_TIME,
            ),
            type: 'EMAIL_VERIFICATION',
          },
        });

        return { id, user };
      });

      const response = await request(app.getHttpServer())
        .post('/confirmation/resend')
        .send({ confirmationId: id })
        .expect(201);

      expect(response.body).toEqual({
        message: 'Confirmation letter has been successfully sent',
        confirmationId: expect.any(String),
      });
      expect(response.body.confirmationId).toHaveLength(36);

      const { emailConfirmed, Confirmation } =
        await prismaService.user.findUnique({
          where: { id: user.id },
          include: { Confirmation: true },
        });

      expect(emailConfirmed).toBeFalsy();
      expect(Confirmation).toHaveLength(1);
      expect(Confirmation[0].id).not.toBe(id);
    });
  });
});
