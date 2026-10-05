import * as request from 'supertest';
import { Test } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { PrismaService } from 'src/prisma-database/prisma.service';
import * as bcrypt from 'bcrypt';
import { AppModule } from 'src/app.module';
import mockUsers from '../utils/mockData/users';
import { JwtService } from '@nestjs/jwt';
import { ThrottlerStorage } from '@nestjs/throttler';
import * as cookieParser from 'cookie-parser';
import decodeSignedCookie from '../utils/decodeSignedCookie';
import { ConfigService } from '@nestjs/config';

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
    await prismaService.user.deleteMany();
    await prismaService.token.deleteMany();
    await prismaService.confirmation.deleteMany();
  };

  afterAll(async () => {
    await clearDB();
    await app.close();
  });

  beforeEach(async () => await clearDB());

  describe('/auth/sign-in (POST)', () => {
    it('should return code 400 & validation error', async () => {
      for (const user of mockUsers.signInInvalidParams) {
        const response = await request(app.getHttpServer())
          .post('/auth/sign-in')
          .send(user)
          .expect(400);

        expect(response.body).toEqual({
          statusCode: 400,
          error: 'Bad Request',
          message: expect.any(Array || String),
        });
        expect(response.headers['set-cookie']).toBeFalsy();
      }
    });

    it('should return http code 401 & UnauthorizedException (Users not found)', async () => {
      for (const { email, password } of mockUsers.validSignUpParams) {
        const response = await request(app.getHttpServer())
          .post('/auth/sign-in')
          .send({ email, password })
          .expect(401);

        expect(response.body).toEqual({
          statusCode: 401,
          error: 'Unauthorized',
          message: 'Wrong email or password',
        });
        expect(response.headers['set-cookie']).toBeFalsy();
      }
    });

    it('should return http code 401 & UnauthorizedException (Incorrect credentials)', async () => {
      const mockData = mockUsers.validSignUpParams.map(
        ({ email, password }) => ({
          email,
          password: bcrypt.hashSync(password, saltRounds),
          emailConfirmed: true,
        }),
      );

      const users = await prismaService.user.createManyAndReturn({
        data: mockData,
      });

      for (const { email } of users) {
        const response = await request(app.getHttpServer())
          .post('/auth/sign-in')
          .send({ email, password: crypto.randomUUID() })
          .expect(401);

        expect(response.body).toEqual({
          statusCode: 401,
          error: 'Unauthorized',
          message: 'Wrong email or password',
        });
        expect(response.headers['set-cookie']).toBeFalsy();
      }
    });

    it('should return http code 201 & access and refresh tokens set to cookie', async () => {
      const mockConfirmedUsersWithHashedPasswords =
        mockUsers.validSignUpParams.map(({ email, password }) => ({
          email,
          password: bcrypt.hashSync(password, saltRounds),
          emailConfirmed: true,
        }));

      await prismaService.user.createMany({
        data: mockConfirmedUsersWithHashedPasswords,
      });

      for (const { email, password } of mockUsers.validSignUpParams) {
        const response = await request(app.getHttpServer())
          .post('/auth/sign-in')
          .send({ email, password })
          .expect(201);

        expect(response.body).toEqual({
          message: 'User successfully logged in',
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
      }
    });

    it('should return http code 403 & ForbiddenException (Email address is not confirmed)', async () => {
      const mockUsersWithHashedPasswords = mockUsers.validSignUpParams.map(
        ({ email, password }) => ({
          email,
          password: bcrypt.hashSync(password, saltRounds),
        }),
      );

      await prismaService.user.createMany({
        data: mockUsersWithHashedPasswords,
      });

      for (const { email, password } of mockUsers.validSignUpParams) {
        const response = await request(app.getHttpServer())
          .post('/auth/sign-in')
          .send({ email, password })
          .expect(403);

        expect(response.body).toEqual({
          statusCode: 403,
          error: 'Forbidden',
          message: 'Email address is not confirmed',
        });
        expect(response.headers['set-cookie']).toBeFalsy();
      }
    });

    it('should return http code 401 && Two-Factor Auth failed', async () => {
      const mockUser = {
        email: 'example123321@gmail.com',
        password: '837poiasbfjhk12',
        emailConfirmed: true,
        twoFactorAuthEnabled: true,
        twoFactorCountry: 'Any country',
      };

      await prismaService.user.create({
        data: {
          ...mockUser,
          password: bcrypt.hashSync(mockUser.password, saltRounds),
          twoFactorCountry: bcrypt.hashSync(
            mockUser.twoFactorCountry,
            saltRounds,
          ),
        },
      });

      const response = await request(app.getHttpServer())
        .post('/auth/sign-in')
        .set('x-client-ip', '176.9.113.53')
        .send({ password: mockUser.password, email: mockUser.email })
        .expect(401);

      expect(response.body).toEqual({
        statusCode: 401,
        error: 'Unauthorized',
        message:
          'Suspicious activity detected. A verification code has been sent to your email. Please check your inbox and enter the code to proceed',
        confirmationId: expect.any(String),
      });
      expect(response.headers['set-cookie']).toBeFalsy();
      expect(response.body.confirmationId).toHaveLength(36);
      expect(
        await prismaService.confirmation.findUnique({
          where: { id: response.body.confirmationId },
        }),
      ).toMatchObject({
        id: response.body.confirmationId,
        type: 'TWO_FACTOR_AUTH',
      });
    });

    it('should return http code 201 && Auth cookies, 2FA passed successfully', async () => {
      const mockUser = {
        email: 'example123321@gmail.com',
        password: '837poiasbfjhk12',
        emailConfirmed: true,
        twoFactorAuthEnabled: true,
        twoFactorCountry: 'Germany',
      };

      await prismaService.user.create({
        data: {
          ...mockUser,
          password: bcrypt.hashSync(mockUser.password, saltRounds),
          twoFactorCountry: bcrypt.hashSync(
            mockUser.twoFactorCountry,
            saltRounds,
          ),
        },
      });

      const response = await request(app.getHttpServer())
        .post('/auth/sign-in')
        .set('x-client-ip', '176.9.113.53')
        .send({ password: mockUser.password, email: mockUser.email })
        .expect(201);

      expect(response.body).toEqual({
        message: 'User successfully logged in',
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
    });
  });
});
