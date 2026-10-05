import { applyDecorators } from '@nestjs/common';
import {
  ApiOperation,
  ApiBody,
  ApiCreatedResponse,
  ApiUnauthorizedResponse,
  ApiInternalServerErrorResponse,
} from '@nestjs/swagger';
import VerifyConfirmationDTO from '../dto/verify.confirmation.dto';

export function VerifyConfirmationSwaggerDocs() {
  return applyDecorators(
    ApiOperation({
      summary:
        'Verify confirmation and run the post-confirmation function (e.g. confirm email address).',
    }),
    ApiBody({ type: VerifyConfirmationDTO }),
    ApiCreatedResponse({
      description: 'Verification successful',
      examples: {
        email: {
          summary:
            'Email confirmed. Auth cookies has been set in response headers',
          value: {
            message: 'User successfully confirmed email address',
          },
        },
        two_factor_auth: {
          summary:
            'Two-factor auth has been confirmed. Auth cookies has been set in response headers',
          value: {
            message: 'User successfully authorized',
          },
        },
      },
    }),
    ApiUnauthorizedResponse({
      description:
        'A confirmation record was not found, the wrong token was provided, or the token expired',
      examples: {
        wrong_credentials: {
          summary:
            'A confirmation record was not found, or the wrong token was provided',
          value: {
            message:
              'A confirmation record was not found, or the wrong token was provided',
            statusCode: 401,
            error: 'Unauthorized',
          },
        },
        expired: {
          summary: 'Token expired',
          value: {
            message: 'Token expired',
            statusCode: 401,
            error: 'Unauthorized',
          },
        },
      },
    }),
    ApiInternalServerErrorResponse({
      description: 'Default block in switch case',
      example: {
        message: 'Unsupported confirmation type: confirmation type',
        statusCode: 500,
        error: 'Internal Server Error',
      },
    }),
  );
}
