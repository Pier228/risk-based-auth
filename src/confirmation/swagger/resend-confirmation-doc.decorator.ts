import { applyDecorators } from '@nestjs/common';
import {
  ApiOperation,
  ApiBody,
  ApiCreatedResponse,
  ApiNotFoundResponse,
  ApiBadRequestResponse,
  ApiBadGatewayResponse,
} from '@nestjs/swagger';
import ResendConfirmationDTO from '../dto/resend.confirmation.dto';

export function ResendConfirmationSwaggerDocs() {
  return applyDecorators(
    ApiOperation({
      summary: 'Recreate confirmation record and resend confirmation letter',
    }),
    ApiBody({ type: ResendConfirmationDTO }),
    ApiCreatedResponse({
      description:
        'Confirmation letter has been resend & confirmation record has been recreated',
      example: {
        message: 'Confirmation letter has been successfully sent',
        confirmationId: '42582227-c6b6-43ce-9dcc-fac56fd355e3',
      },
    }),
    ApiNotFoundResponse({
      description: 'Confirmation record not found',
      example: {
        message: 'Confirmation record not found',
        statusCode: 404,
        error: 'Not Found',
      },
    }),
    ApiBadRequestResponse({
      description: 'Email resend eligibility is not allowed',
      example: {
        message: 'Please wait a bit before requesting again.',
        secondsRemaining: 120,
        minutesRemaining: 2,
        statusCode: 400,
        error: 'Bad Request',
        retryAt: new Date(Date.now() + 120 * 1000),
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
