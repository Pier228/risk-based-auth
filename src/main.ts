import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import helmet from 'helmet';
import * as cookieParser from 'cookie-parser';
import { ConfigService } from '@nestjs/config';
import { PROXY_HEADERS } from './common/globals';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  // Configure global validation pipe for all incoming requests
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true, // Automatically transform payloads to DTO instances
      whitelist: true, // Remove properties not defined in DTO classes
    }),
  );

  app.enableCors({
    origin: configService.get('CORS_ALLOWED_ORIGIN') || '*', // Allow specified origins or all (*)
    methods: ['GET', 'POST', 'PATCH', 'DELETE'], // Allowed HTTP methods
    credentials: true, // Allows sending credentials (cookies, auth headers)
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'x-visitor-id', // Custom header for visitorId from FingerprintJS
      ...PROXY_HEADERS,
    ], // Allowed headers in requests
  });

  app.use(cookieParser(configService.getOrThrow('COOKIE_SECRET')));
  app.use(helmet()); // Add security HTTP headers using helmet middleware

  const config = new DocumentBuilder() // Configure Swagger/OpenAPI documentation
    .setTitle('Level 3 JWT-based auth Documentation')
    .setVersion('1.0')
    .addCookieAuth(
      'auth-cookies',
      {
        type: 'apiKey',
        in: 'cookie',
        name: 'access_token',
        description:
          'Uses both access_token and refresh_token HttpOnly cookies',
      },
      'cookie-auth',
    )
    .build();
  const documentFactory = () => SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, documentFactory);

  await app.listen(configService.get('PORT') ?? 3000); // Start the application on the specified port
}
bootstrap();
