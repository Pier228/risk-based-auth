import {
  MiddlewareConsumer,
  Module,
  NestModule,
  RequestMethod,
} from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { AuthModule } from './auth/auth.module';
import { PrismaDatabaseModule } from './prisma-database/prisma-database.module';
import { ACCESS_TOKEN_CONFIG } from './common/globals';
import { ScheduleModule } from '@nestjs/schedule';
import { CleanupService } from './jobs/cleanup.service';
import { ConfirmationModule } from './confirmation/confirmation.module';
import { CacheModule } from '@nestjs/cache-manager';
import { createKeyv, Keyv } from '@keyv/redis';
import { SecurityModule } from './security/security.module';
import { SecurityMiddleware } from './common/middlewares/security/security.middleware';
import { TokenModule } from './shared/token/token.module';

@Module({
  imports: [
    ConfigModule.forRoot(), // Loads environment variables from .env file
    JwtModule.register({
      global: true,
      secret: process.env.JWT_SECRET, // Secret key from environment variables
      signOptions: { expiresIn: ACCESS_TOKEN_CONFIG.EXPIRES_IN }, // Token expiration time
    }),
    ThrottlerModule.forRoot({
      // Configures rate limiting (throttling) for API endpoints
      throttlers: [
        {
          ttl: 60000, // Time-to-live: 60,000ms = 1 minute
          limit: 60, // Maximum 60 requests per IP per minute
        },
      ],
    }),
    ScheduleModule.forRoot(), // Task scheduling
    CacheModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      isGlobal: true,
      useFactory: async (configService: ConfigService) => {
        const redisUrl = configService.get<string>('REDIS_CONNECT');
        const redisStore = createKeyv(redisUrl);
        redisStore.on('error', (err) => {
          console.warn('Redis Cache connection error:', err?.message || err);
        });
        const memoryStore = new Keyv();
        return {
          stores: [redisStore, memoryStore],
          ttl: ACCESS_TOKEN_CONFIG.MAX_AGE,
        };
      },
    }),
    AuthModule,
    PrismaDatabaseModule,
    ConfirmationModule,
    SecurityModule,
    TokenModule,
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard, // Applies rate limiting globally to all routes
    },
    CleanupService,
  ],
})
// Adding security middleware, which will check the JWT in requests
export class AppModule implements NestModule {
  private readonly publicRoutes = [
    { path: 'auth/sign-in', method: RequestMethod.POST },
    { path: 'auth/sign-up', method: RequestMethod.POST },
    { path: 'confirmation(.*)', method: RequestMethod.POST },
  ];

  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(SecurityMiddleware)
      .exclude(...this.publicRoutes)
      .forRoutes('*'); // For all routes except public
  }
}
