import { applyDecorators } from '@nestjs/common';
import {
  ApiOperation,
  ApiCreatedResponse,
  ApiCookieAuth,
} from '@nestjs/swagger';

export function SignOutSwaggerDocs() {
  return applyDecorators(
    ApiOperation({ summary: 'Log out user' }),
    ApiCookieAuth('cookie-auth'),
    ApiCreatedResponse({
      description: 'User successfully logged out and auth cookies cleared',
      example: { message: 'Successfully signed out' },
    }),
  );
}
