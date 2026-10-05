import * as request from 'supertest';
import { Test } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { PrismaService } from 'src/prisma-database/prisma.service';
import * as bcrypt from 'bcrypt';
import { AppModule } from 'src/app.module';
import mockUsers from '../utils/mockData/users';
import { ThrottlerStorage } from '@nestjs/throttler';
import * as cookieParser from 'cookie-parser';
import decodeSignedCookie from '../utils/decodeSignedCookie';
import { ConfigService } from '@nestjs/config';

describe('Auth Controller (e2e)', () => {
  let app: INestApplication;
  let prismaService: PrismaService;
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

  describe('/auth/sign-out (POST)', () => {
    it('should return code 201 & clear access token cookie', async () => {
      const { email, password } = mockUsers.validSignUpParams[0];

      await prismaService.user.create({
        data: {
          email,
          password: bcrypt.hashSync(password, saltRounds),
          emailConfirmed: true,
        },
      });

      const res = await request(app.getHttpServer())
        .post('/auth/sign-in')
        .send({ email, password })
        .expect(201);

      expect(res.body).toEqual({
        message: 'User successfully logged in',
      });
      expect(res.headers['set-cookie'].length).toBeGreaterThanOrEqual(2);

      const response = await request(app.getHttpServer())
        .post('/auth/sign-out')
        .set('Cookie', res.headers['set-cookie'][0])
        .expect(201);

      expect(response.body).toEqual({
        message: 'Successfully signed out',
      });
      expect(response.headers['set-cookie']).toHaveLength(1);

      const accessToken = decodeSignedCookie(
        response.headers['set-cookie'][0],
        'access_token',
      );

      expect(accessToken).toBeFalsy();
    });

    it('should return code 201 & clear refresh token cookie', async () => {
      const { email, password } = mockUsers.validSignUpParams[0];

      await prismaService.user.create({
        data: {
          email,
          password: bcrypt.hashSync(password, saltRounds),
          emailConfirmed: true,
        },
      });

      const res = await request(app.getHttpServer())
        .post('/auth/sign-in')
        .send({ email, password })
        .expect(201);

      expect(res.body).toEqual({
        message: 'User successfully logged in',
      });
      expect(res.headers['set-cookie'].length).toBeGreaterThanOrEqual(2);

      const response = await request(app.getHttpServer())
        .post('/auth/sign-out')
        .set('Cookie', res.headers['set-cookie'][1])
        .expect(201);

      expect(response.body).toEqual({
        message: 'Successfully signed out',
      });
      expect(response.headers['set-cookie']).toHaveLength(1);

      const refreshToken = decodeSignedCookie(
        response.headers['set-cookie'][0],
        'refresh_token',
      );

      expect(refreshToken).toBeFalsy();
    });

    it('should return http code 201 & Successfully signed out', async () => {
      const mockConfirmedUsersWithHashedPasswords =
        mockUsers.validSignUpParams.map(({ email, password }) => ({
          email,
          password: bcrypt.hashSync(password, saltRounds),
          emailConfirmed: true,
        }));

      await prismaService.user.createMany({
        data: mockConfirmedUsersWithHashedPasswords,
      });

      for (const user of mockUsers.validSignUpParams) {
        const res = await request(app.getHttpServer())
          .post('/auth/sign-in')
          .send(user)
          .expect(201);

        expect(res.body).toEqual({
          message: 'User successfully logged in',
        });

        expect(res.headers['set-cookie'].length).toBeGreaterThanOrEqual(2);

        const response = await request(app.getHttpServer())
          .post('/auth/sign-out')
          .set('Cookie', res.headers['set-cookie'])
          .expect(201);

        expect(response.body).toEqual({
          message: 'Successfully signed out',
        });

        const accessToken = decodeSignedCookie(
          response.headers['set-cookie'][0],
          'access_token',
        );
        const refreshToken = decodeSignedCookie(
          response.headers['set-cookie'][1],
          'refresh_token',
        );

        expect(accessToken).toBeFalsy();
        expect(refreshToken).toBeFalsy();
      }
    });
  });
});
