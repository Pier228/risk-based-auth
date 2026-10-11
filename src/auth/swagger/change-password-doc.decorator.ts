import { applyDecorators } from '@nestjs/common';
import {
  ApiOperation,
  ApiBody,
  ApiOkResponse,
  ApiBadRequestResponse,
  ApiUnauthorizedResponse,
  ApiNotFoundResponse,
  ApiCookieAuth,
} from '@nestjs/swagger';
import ChangePasswordDTO from '../dto/change.password.dto';

export function ChangePasswordSwaggerDocs() {
  return applyDecorators(
    ApiOperation({ summary: 'Change current user password' }),
    ApiCookieAuth('cookie-auth'),
    ApiBody({ type: ChangePasswordDTO }),
    ApiOkResponse({
      description:
        'Password successfully changed, old tokens invalidated, and new auth cookies set',
      example: { message: 'Password has been successfully changed' },
    }),
    ApiBadRequestResponse({
      description: 'Incorrect current password or new password is the same',
      examples: {
        wrong_password: {
          summary: 'Wrong current password',
          value: {
            statusCode: 400,
            message: 'Incorrect current password',
            error: 'Bad Request',
          },
        },
        same_password: {
          summary: 'Same password provided',
          value: {
            statusCode: 400,
            message: 'New password must be different from current password',
            error: 'Bad Request',
          },
        },
      },
    }),
    ApiUnauthorizedResponse({
      description: 'Unauthorized request',
      example: {
        statusCode: 401,
        message: 'No valid token provided',
        error: 'Unauthorized',
      },
    }),
    ApiNotFoundResponse({
      description: 'User not found',
      example: {
        statusCode: 404,
        message: 'User not found',
        error: 'Not Found',
      },
    }),
  );
}