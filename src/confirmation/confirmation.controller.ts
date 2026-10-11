import { Body, Controller, Post, Req, Res } from '@nestjs/common';
import { ConfirmationService } from './confirmation.service';
import { Throttle } from '@nestjs/throttler';
import { ResendConfirmationSwaggerDocs } from './swagger/resend-confirmation-doc.decorator';
import VerifyConfirmationDTO from './dto/verify.confirmation.dto';
import ResendConfirmationDTO from './dto/resend.confirmation.dto';
import { VerifyConfirmationSwaggerDocs } from './swagger/verify-confirmation-doc.decorator';
import { Response } from 'express';
import type RequestWithId from 'src/common/entities/IRequestWithId';

@Controller('confirmation')
export class ConfirmationController {
  constructor(private readonly confirmationService: ConfirmationService) {}

  @VerifyConfirmationSwaggerDocs()
  @Post('verify')
  @Throttle({ default: { limit: 5, ttl: 5 * 60 * 1000 } }) // 5 requests per 5 minutes
  async handleConfirmation(
    @Body() body: VerifyConfirmationDTO,
    @Res({ passthrough: true }) response: Response,
    @Req() req: RequestWithId,
  ) {
    return this.confirmationService.handleConfirmation(body, response, req);
  }

  @ResendConfirmationSwaggerDocs()
  @Post('resend')
  @Throttle({ default: { limit: 8, ttl: 5 * 60 * 1000 } }) // 8 requests per 5 minutes
  async resendConfirmation(@Body() { confirmationId }: ResendConfirmationDTO) {
    return this.confirmationService.resendConfirmation(confirmationId);
  }
}
