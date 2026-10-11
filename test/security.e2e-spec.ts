import { INestApplication, ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { AppModule } from 'src/app.module';
import { PrismaService } from 'src/prisma-database/prisma.service';
import cookieParser from 'cookie-parser';
import { JwtService } from '@nestjs/jwt';
import request from 'supertest';
import * as cookieSignature from 'cookie-signature';

describe('Security Controller (e2e)', () => {
  let app: INestApplication;
  let prismaService: PrismaService;
  let cookieSecret: string;
  let jwtService: JwtService;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();
    const configService = app.get(ConfigService);
    cookieSecret = configService.getOrThrow('COOKIE_SECRET');

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

  describe('/security/two-factor-auth (PATCH)', () => {
    it('should return 200, enable 2FA, link TrustedDevice and create AuthLog', async () => {
      const user = await prismaService.user.create({
        data: { email: 'enable-2fa@gmail.com', password: 'password123' },
      });

      const accessToken = await jwtService.signAsync({ id: user.id });
      const signedCookie =
        's:' + cookieSignature.sign(accessToken, cookieSecret);

      const response = await request(app.getHttpServer())
        .patch('/security/two-factor-auth')
        .set('Cookie', [`access_token=${signedCookie}`])
        .set('x-client-ip', '176.9.113.53')
        .set('x-visitor-id', 'test-device-uuid-123')
        .expect(200);

      expect(response.body).toEqual({
        message: 'Two-factor authentication has been successfully enabled',
      });

      const updatedUser = await prismaService.user.findUnique({
        where: { id: user.id },
        include: { authLogs: true, trustedDevices: true },
      });

      expect(updatedUser?.twoFactorAuthEnabled).toBe(true);
      expect(updatedUser?.trustedDevices).toHaveLength(1);
      expect(updatedUser?.trustedDevices[0].visitorId).toBe(
        'test-device-uuid-123',
      );
    });

    it('should return 200, disable 2FA and wipe all security logs/devices', async () => {
      const user = await prismaService.user.create({
        data: {
          email: 'disable-2fa@gmail.com',
          password: 'password123',
          twoFactorAuthEnabled: true,
          trustedDevices: {
            create: { visitorId: 'legacy-device-id' },
          },
          authLogs: {
            create: { ip: '1.2.3.4' },
          },
        },
      });

      const accessToken = await jwtService.signAsync({ id: user.id });
      const signedCookie =
        's:' + cookieSignature.sign(accessToken, cookieSecret);

      const response = await request(app.getHttpServer())
        .patch('/security/two-factor-auth')
        .set('Cookie', [`access_token=${signedCookie}`])
        .expect(200);

      expect(response.body).toEqual({
        message: 'Two-factor authentication has been successfully disabled',
      });

      const updatedUser = await prismaService.user.findUnique({
        where: { id: user.id },
        include: { authLogs: true, trustedDevices: true },
      });

      expect(updatedUser?.twoFactorAuthEnabled).toBe(false);
      expect(updatedUser?.trustedDevices).toHaveLength(0);
      expect(updatedUser?.authLogs).toHaveLength(0);
    });

    it('should return 404 when authenticated user is not found in database', async () => {
      const accessToken = await jwtService.signAsync({
        id: crypto.randomUUID(),
      });
      const signedCookie =
        's:' + cookieSignature.sign(accessToken, cookieSecret);

      const response = await request(app.getHttpServer())
        .patch('/security/two-factor-auth')
        .set('Cookie', [`access_token=${signedCookie}`])
        .expect(404);

      expect(response.body).toEqual({
        error: 'Not Found',
        message: 'User not found',
        statusCode: 404,
      });
    });
  });
});
