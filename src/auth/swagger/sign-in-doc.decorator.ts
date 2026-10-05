import { applyDecorators } from '@nestjs/common';
import {
  ApiOperation,
  ApiBody,
  ApiCreatedResponse,
  ApiUnauthorizedResponse,
  ApiForbiddenResponse,
} from '@nestjs/swagger';
import SignInDTO from '../dto/sign.in.dto';

export function SignInSwaggerDocs() {
  return applyDecorators(
    ApiOperation({ summary: 'Log in an existing user' }),
    ApiBody({ type: SignInDTO }),
    ApiCreatedResponse({
      description:
        'User successfully authenticated, and the token is set up in cookies',
      example: { message: 'User successfully logged in' },
    }),
    ApiUnauthorizedResponse({
      description: 'Invalid credentials or failed to complete two-factor auth',
      examples: {
        invalid_params: {
          summary: 'Invalid login or password',
          value: {
            message: 'Wrong login or password',
            statusCode: 401,
            error: 'Unauthorized',
          },
        },
        failed_two_factor_auth: {
          summary: 'Failed to pass two factor auth',
          value: {
            message:
              'Suspicious activity detected. A verification code has been sent to your email. Please check your inbox and enter the code to proceed',
            confirmationId: '4d0e0eac-ea44-408b-a707-166143136c68',
            statusCode: 401,
            error: 'Unauthorized',
          },
        },
      },
    }),
    ApiForbiddenResponse({
      description: 'Email address is not confirmed',
      example: {
        message: 'Email address is not confirmed',
        statusCode: 403,
        error: 'Forbidden',
      },
    }),
  );
}
