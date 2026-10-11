import request from 'supertest';
import { Test } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { PrismaService } from 'src/prisma-database/prisma.service';
import { AppModule } from 'src/app.module';
import { JwtService } from '@nestjs/jwt';
import { ThrottlerStorage } from '@nestjs/throttler';
import cookieParser from 'cookie-parser';
import decodeSignedCookie from '../utils/decodeSignedCookie';
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

  describe('/confirmation/verify (POST)', () => {
    it('should return 401 if wrong token code is provided', async () => {
      const user = await prismaService.user.create({
        data: { email: 'verify-fail@gmail.com', password: 'password123' },
      });

      const confirmation = await prismaService.confirmation.create({
        data: {
          userId: user.id,
          token: await bcryptService.hash('123456'),
          expiresAt: new Date(Date.now() + 300000),
          type: 'EMAIL_VERIFICATION',
        },
      });

      const response = await request(app.getHttpServer())
        .post('/confirmation/verify')
        .send({ token: '000000', confirmationId: confirmation.id })
        .expect(401);

      expect(response.body.message).toBe(
        'A confirmation record was not found, or the wrong token was provided',
      );
    });

    it('should confirm email, issue tokens and delete confirmation record', async () => {
      const token = '654321';
      const user = await prismaService.user.create({
        data: {
          email: 'confirm-email@gmail.com',
          password: 'password123',
          emailConfirmed: false,
        },
      });

      const confirmation = await prismaService.confirmation.create({
        data: {
          userId: user.id,
          token: await bcryptService.hash(token),
          expiresAt: new Date(Date.now() + 300000),
          type: 'EMAIL_VERIFICATION',
        },
      });

      const response = await request(app.getHttpServer())
        .post('/confirmation/verify')
        .send({ token, confirmationId: confirmation.id })
        .expect(201);

      expect(response.body).toEqual({
        message: 'User successfully confirmed email address',
      });

      const accessToken = decodeSignedCookie(
        response.headers['set-cookie'][0],
        'access_token',
      );
      expect(accessToken).toBeTruthy();

      const userInDb = await prismaService.user.findUnique({
        where: { id: user.id },
      });
      expect(userInDb?.emailConfirmed).toBe(true);

      const confirmationInDb = await prismaService.confirmation.findUnique({
        where: { id: confirmation.id },
      });
      expect(confirmationInDb).toBeNull();
    });

    it('should verify 2FA OTP, issue tokens and link device to TrustedDevice list', async () => {
      const token = '789123';
      const user = await prismaService.user.create({
        data: {
          email: 'confirm-2fa@gmail.com',
          password: 'password123',
          emailConfirmed: true,
          twoFactorAuthEnabled: true,
        },
      });

      const confirmation = await prismaService.confirmation.create({
        data: {
          userId: user.id,
          token: await bcryptService.hash(token),
          expiresAt: new Date(Date.now() + 300000),
          type: 'TWO_FACTOR_AUTH',
        },
      });

      const response = await request(app.getHttpServer())
        .post('/confirmation/verify')
        .set('x-visitor-id', 'new-authenticated-tablet')
        .send({ token, confirmationId: confirmation.id })
        .expect(201);

      expect(response.body).toEqual({
        message: 'User successfully authorized',
      });

      const device = await prismaService.trustedDevice.findFirst({
        where: { userId: user.id, visitorId: 'new-authenticated-tablet' },
      });
      expect(device).toBeTruthy();
    });
  });
});
