import { applyDecorators } from '@nestjs/common';
import {
  ApiOperation,
  ApiCookieAuth,
  ApiOkResponse,
  ApiNotFoundResponse,
} from '@nestjs/swagger';

export function TwoFactorAuthSwaggerDocs() {
  return applyDecorators(
    ApiOperation({
      summary: "Enable or disable a user's two-factor authentication",
    }),
    ApiCookieAuth('cookie-auth'),
    ApiOkResponse({
      description: "Enable or disable a user's two-factor authentication",
      example: {
        message: `Two-factor authentication has been successfully enabled`,
      },
    }),
    ApiNotFoundResponse({
      description: 'User with this id not found',
      example: {
        message: 'User not found',
        statusCode: 404,
        error: 'Not Found',
      },
    }),
  );
}
