import { INestApplication, ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { AppModule } from 'src/app.module';
import { PrismaService } from 'src/prisma-database/prisma.service';
import * as cookieParser from 'cookie-parser';
import { JwtService } from '@nestjs/jwt';
import * as request from 'supertest';
import * as cookieSignature from 'cookie-signature';
import { BcryptModule } from 'src/shared/bcrypt/bcrypt.module';
import { BcryptService } from 'src/shared/bcrypt/bcrypt.service';

describe('Security Controller (e2e)', () => {
  let app: INestApplication;
  let prismaService: PrismaService;
  let cookieSecret: string;
  let jwtService: JwtService;
  let bcryptService: BcryptService;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule, BcryptModule],
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
    bcryptService = moduleRef.get<BcryptService>(BcryptService);
    await app.init();
  });

  const clearDB = async () => {
    await prismaService.user.deleteMany();
  };

  afterAll(async () => {
    await clearDB();
    await app.close();
  });

  beforeEach(async () => await clearDB());

  describe('/security/two-factor-auth (PATCH)', () => {
    it('should return http code 200 & turn on 2FA & set 2FA country', async () => {
      const { id, twoFactorAuthEnabled, twoFactorCountry } =
        await prismaService.user.create({
          data: { email: 'example@gmail.com', password: '12323' },
        });

      expect(twoFactorAuthEnabled).toBe(false);
      expect(twoFactorCountry).toBeNull();

      const accessToken = await jwtService.signAsync({ id });
      const signedCookie =
        's:' + cookieSignature.sign(accessToken, cookieSecret);

      const response = await request(app.getHttpServer())
        .patch('/security/two-factor-auth')
        .set('Cookie', [`access_token=${signedCookie}`])
        .set('x-client-ip', '176.9.113.53')
        .expect(200);

      expect(response.body).toEqual({
        message: 'Two-factor authentication has been successfully enabled',
      });

      const user = await prismaService.user.findUnique({ where: { id } });

      expect(user.twoFactorAuthEnabled).toBe(true);
      expect(user.twoFactorCountry).toBeTruthy();

      const isMatch = await bcryptService.compare(
        'Germany',
        user.twoFactorCountry,
      );
      expect(isMatch).toBe(true);
    });

    it('should return http code 200 & turn on 2FA & set null as 2FA country', async () => {
      const { id, twoFactorAuthEnabled, twoFactorCountry } =
        await prismaService.user.create({
          data: { email: 'example@gmail.com', password: '12323' },
        });

      expect(twoFactorAuthEnabled).toBe(false);
      expect(twoFactorCountry).toBeNull();

      const accessToken = await jwtService.signAsync({ id });
      const signedCookie =
        's:' + cookieSignature.sign(accessToken, cookieSecret);

      const response = await request(app.getHttpServer())
        .patch('/security/two-factor-auth')
        .set('Cookie', [`access_token=${signedCookie}`])
        .expect(200);

      expect(response.body).toEqual({
        message: 'Two-factor authentication has been successfully enabled',
      });

      const user = await prismaService.user.findUnique({ where: { id } });

      expect(user.twoFactorAuthEnabled).toBe(true);
      expect(user.twoFactorCountry).toBe(null);
    });

    it('should return http code 200 & turn off 2FA & clear 2FA country', async () => {
      const { id } = await prismaService.user.create({
        data: {
          email: 'example@gmail.com',
          password: '12323',
          twoFactorAuthEnabled: true,
          twoFactorCountry: await bcryptService.hash('Germany'),
        },
      });

      const accessToken = await jwtService.signAsync({ id });
      const signedCookie =
        's:' + cookieSignature.sign(accessToken, cookieSecret);

      const response = await request(app.getHttpServer())
        .patch('/security/two-factor-auth')
        .set('Cookie', [`access_token=${signedCookie}`])
        .expect(200);

      expect(response.body).toEqual({
        message: 'Two-factor authentication has been successfully disabled',
      });

      const user = await prismaService.user.findUnique({ where: { id } });

      expect(user.twoFactorAuthEnabled).toBe(false);
      expect(user.twoFactorCountry).toBe(null);
    });

    it('should return http code 404 & user not found', async () => {
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
