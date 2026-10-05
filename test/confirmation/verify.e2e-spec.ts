import * as request from 'supertest';
import { Test } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { PrismaService } from 'src/prisma-database/prisma.service';
import { AppModule } from 'src/app.module';
import { JwtService } from '@nestjs/jwt';
import { ThrottlerStorage } from '@nestjs/throttler';
import * as cookieParser from 'cookie-parser';
import decodeSignedCookie from '../utils/decodeSignedCookie';
import { mockEmailConfirmation } from 'test/utils/mockData/email.confirmation';
import { ConfigService } from '@nestjs/config';
import { BcryptService } from 'src/shared/bcrypt/bcrypt.service';
import { BcryptModule } from 'src/shared/bcrypt/bcrypt.module';

describe('Confirmation Controller (e2e)', () => {
  let app: INestApplication;
  let prismaService: PrismaService;
  let jwtService: JwtService;
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
    jwtService = moduleRef.get<JwtService>(JwtService);
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

  describe('/confirmation/verify (POST)', () => {
    it('should return code 400 & validation error', async () => {
      for (const confirmation of mockEmailConfirmation.invalid) {
        const response = await request(app.getHttpServer())
          .post('/confirmation/verify')
          .send(confirmation)
          .expect(400);

        expect(response.body).toEqual({
          statusCode: 400,
          error: 'Bad Request',
          message: expect.any(Array || String),
        });
        expect(response.headers['set-cookie']).toBeFalsy();
      }
    });

    it('should return http code 401 & UnauthorizedException (not found)', async () => {
      const response = await request(app.getHttpServer())
        .post('/confirmation/verify')
        .send({ token: '123123', confirmationId: crypto.randomUUID() })
        .expect(401);

      expect(response.body).toEqual({
        statusCode: 401,
        error: 'Unauthorized',
        message:
          'A confirmation record was not found, or the wrong token was provided',
      });
      expect(response.headers['set-cookie']).toBeFalsy();
    });

    it('should return http code 401 & UnauthorizedException (incorrect token)', async () => {
      const token = '123456';
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
            token: await bcryptService.hash(token),
            expiresAt: new Date(Date.now() + 1000 * 60 * 5),
            type: 'EMAIL_VERIFICATION',
          },
        });

        return { id };
      });

      const response = await request(app.getHttpServer())
        .post('/confirmation/verify')
        .send({ token: '000000', confirmationId: id })
        .expect(401);

      expect(response.body).toEqual({
        statusCode: 401,
        error: 'Unauthorized',
        message:
          'A confirmation record was not found, or the wrong token was provided',
      });
      expect(response.headers['set-cookie']).toBeFalsy();
    });

    it('should return http code 401 & UnauthorizedException (token expired)', async () => {
      const token = '321123';
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
            token: await bcryptService.hash(token),
            expiresAt: new Date(Date.now() - 1000 * 60 * 5),
            type: 'EMAIL_VERIFICATION',
          },
        });

        return { id };
      });

      const response = await request(app.getHttpServer())
        .post('/confirmation/verify')
        .send({ token, confirmationId: id })
        .expect(401);

      expect(response.body).toEqual({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Token expired',
      });
      expect(response.headers['set-cookie']).toBeFalsy();
    });

    it('should return http code 201 & access and refresh tokens set to cookie & user email confirmed & confirmation deleted', async () => {
      const token = '543765';
      const { id, user } = await prismaService.$transaction(async (tx) => {
        const user = await tx.user.create({
          data: {
            email: Date.now() + '@gmail.com',
            password: Date.now().toString(),
          },
        });

        const { id } = await tx.confirmation.create({
          data: {
            userId: user.id,
            token: await bcryptService.hash(token),
            expiresAt: new Date(Date.now() + 1000 * 60 * 5),
            type: 'EMAIL_VERIFICATION',
          },
        });

        return { user, id };
      });

      const response = await request(app.getHttpServer())
        .post('/confirmation/verify')
        .send({ token, confirmationId: id })
        .expect(201);

      expect(response.body).toEqual({
        message: 'User successfully confirmed email address',
      });

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

      const payload = await jwtService.verifyAsync(accessToken as string);
      expect(payload).toHaveProperty('id');
      expect(payload.id).toHaveLength(36);
      expect(refreshToken).toHaveLength(36);

      const { emailConfirmed, Confirmation } =
        await prismaService.user.findUnique({
          where: { id: user.id },
          include: { Confirmation: true },
        });

      expect(emailConfirmed).toBeTruthy();
      expect(Confirmation).toHaveLength(0);
    });

    it('should return http code 201 & access and refresh tokens set to cookie & sign-in confirmed & confirmation deleted', async () => {
      const token = '321543';
      const { id, user } = await prismaService.$transaction(async (tx) => {
        const user = await tx.user.create({
          data: {
            email: Date.now() + '@gmail.com',
            password: Date.now().toString(),
            emailConfirmed: true,
            twoFactorAuthEnabled: true,
            twoFactorCountry: await bcryptService.hash('Germany'),
          },
        });

        const { id } = await tx.confirmation.create({
          data: {
            userId: user.id,
            token: await bcryptService.hash(token),
            expiresAt: new Date(Date.now() + 1000 * 60 * 5),
            type: 'TWO_FACTOR_AUTH',
          },
        });

        return { user, id };
      });

      const response = await request(app.getHttpServer())
        .post('/confirmation/verify')
        .send({ token, confirmationId: id })
        .expect(201);

      expect(response.body).toEqual({
        message: 'User successfully authorized',
      });

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

      const payload = await jwtService.verifyAsync(accessToken as string);
      expect(payload).toHaveProperty('id');
      expect(payload.id).toHaveLength(36);
      expect(refreshToken).toHaveLength(36);

      const { Confirmation } = await prismaService.user.findUnique({
        where: { id: user.id },
        include: { Confirmation: true },
      });

      expect(Confirmation).toHaveLength(0);
    });
  });
});
