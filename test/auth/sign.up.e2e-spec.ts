import * as request from 'supertest';
import { Test } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { PrismaService } from 'src/prisma-database/prisma.service';
import { AppModule } from 'src/app.module';
import mockUsers from '../utils/mockData/users';
import { ThrottlerStorage } from '@nestjs/throttler';
import * as cookieParser from 'cookie-parser';
import { ConfigService } from '@nestjs/config';

describe('Auth Controller (e2e)', () => {
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
    await prismaService.user.deleteMany();
    await prismaService.profile.deleteMany();
    await prismaService.confirmation.deleteMany();
  };

  afterAll(async () => {
    await clearDB();
    await app.close();
  });

  beforeEach(async () => await clearDB());

  describe('/auth/sign-up (POST)', () => {
    it('should create user with profile & email confirmation, then send confirmation email and return 201', async () => {
      for (const user of mockUsers.validSignUpParams) {
        const response = await request(app.getHttpServer())
          .post('/auth/sign-up')
          .send(user)
          .expect(201);

        expect(response.body).toEqual({
          message:
            'User created successfully. Please confirm your email to activate your account.',
          confirmationId: expect.any(String),
        });
        expect(response.body.confirmationId).toHaveLength(36);

        const createdUser = await prismaService.user.findUnique({
          where: { email: user.email },
          include: { Token: true, Confirmation: true, Profile: true },
        });

        expect(createdUser).toBeTruthy();
        expect(createdUser).toMatchObject({
          email: user.email,
          emailConfirmed: false,
          twoFactorAuthEnabled: false,
        });

        expect(createdUser.Confirmation).toHaveLength(1);
        expect(createdUser.Confirmation[0].type).toBe('EMAIL_VERIFICATION');

        expect(createdUser.Token).toHaveLength(0);

        expect(createdUser.Profile).toMatchObject({
          name: user.name,
          surname: user.surname,
        });
      }
    });

    it('should delete old, unconfirmed user and register new one', async () => {
      const { email, id } = await prismaService.user.create({
        data: { email: '123213@gmail.com', password: '123123213' },
      });

      const response = await request(app.getHttpServer())
        .post('/auth/sign-up')
        .send({
          email,
          password: '123123123',
          name: 'Pier',
          surname: 'Clinton',
        })
        .expect(201);

      expect(response.body).toEqual({
        message:
          'User created successfully. Please confirm your email to activate your account.',
        confirmationId: expect.any(String),
      });
      expect(response.body.confirmationId).toHaveLength(36);

      const createdUser = await prismaService.user.findUnique({
        where: { email },
        include: { Token: true, Confirmation: true, Profile: true },
      });

      expect(createdUser).toBeTruthy();
      expect(createdUser.email).toBe(email);
      expect(createdUser.emailConfirmed).toBe(false);
      expect(createdUser.id).not.toBe(id);

      expect(createdUser.Confirmation).toHaveLength(1);
      expect(createdUser.Confirmation[0].type).toBe('EMAIL_VERIFICATION');

      expect(createdUser.Token).toHaveLength(0);

      expect(createdUser.Profile).toMatchObject({
        name: 'Pier',
        surname: 'Clinton',
      });
    });

    it('should return code 400 & validation error', async () => {
      for (const user of mockUsers.signUpInvalidParams) {
        const response = await request(app.getHttpServer())
          .post('/auth/sign-up')
          .send(user)
          .expect(400);

        expect(response.body).toEqual({
          statusCode: 400,
          error: 'Bad Request',
          message: expect.any(Array || String),
        });
      }
    });

    it('should return http code 409 & ConflictException - email is already registered', async () => {
      const { email } = await prismaService.user.create({
        data: {
          email: `${Date.now()}@gmail.com`,
          password: crypto.randomUUID(),
          emailConfirmed: true,
        },
      });

      const response = await request(app.getHttpServer())
        .post('/auth/sign-up')
        .send({
          email,
          password: 'random-password',
          name: 'Pier',
          surname: 'Clinton',
        })
        .expect(409);

      expect(response.body).toEqual({
        statusCode: 409,
        error: 'Conflict',
        message: 'User with this email is already registered',
      });
    });

    it('should return http code 409 & ConflictException - A confirmation letter has already been sent', async () => {
      const email = await prismaService.$transaction(async (tx) => {
        const { email, id } = await tx.user.create({
          data: {
            email: `${Date.now()}@gmail.com`,
            password: crypto.randomUUID(),
          },
        });

        await tx.confirmation.create({
          data: {
            type: 'EMAIL_VERIFICATION',
            userId: id,
            token: '123123',
            expiresAt: new Date(Date.now() + 1000 * 60 * 5),
          },
        });

        return email;
      });

      const response = await request(app.getHttpServer())
        .post('/auth/sign-up')
        .send({
          email,
          password: 'random-password',
          name: 'Pier',
          surname: 'Clinton',
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
