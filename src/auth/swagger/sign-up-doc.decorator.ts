import { applyDecorators } from '@nestjs/common';
import {
  ApiOperation,
  ApiBody,
  ApiCreatedResponse,
  ApiConflictResponse,
  ApiBadGatewayResponse,
} from '@nestjs/swagger';
import SignUpDTO from '../dto/sign.up.dto';

export function SignUpSwaggerDocs() {
  return applyDecorators(
    ApiOperation({ summary: 'Register a new user' }),
    ApiBody({ type: SignUpDTO }),
    ApiCreatedResponse({
      description:
        'User successfully registered, and the confirmation email has been sent',
      example: {
        message:
          'User created successfully. Please confirm your email to activate your account.',
        confirmationId: '4f79ddc0-5669-4bec-830f-62c0861a1da1',
      },
    }),
    ApiConflictResponse({
      description:
        'User with this email is already registered || A confirmation letter has already been sent to this email',
      examples: {
        email_unavailable: {
          summary:
            'User with this email is already registered and has confirmed email address',
          value: {
            message: 'User with this email is already registered',
            statusCode: 409,
            error: 'Conflict',
          },
        },
        letter_threshold: {
          summary:
            'The user with this email has already been created, but has an unconfirmed email address, and the resend threshold has not been passed',
          value: {
            message:
              'A confirmation letter has already been sent to this email',
            statusCode: 409,
            error: 'Conflict',
          },
        },
      },
    }),
    ApiBadGatewayResponse({
      description: 'Failed to send email',
      example: {
        message: 'Failed to send email',
        statusCode: 502,
        error: 'Bad Gateway',
      },
    }),
  );
}
