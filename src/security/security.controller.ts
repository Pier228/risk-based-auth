import { Body, Controller, Patch, Req } from '@nestjs/common';
import { SecurityService } from './security.service';
import type RequestWithId from 'src/common/entities/IRequestWithId';
import { TwoFactorAuthSwaggerDocs } from './swagger/two-factor-auth-doc.decorator';
import VisitorIdDTO from './dto/visitor.id.dto';

@Controller('security')
export class SecurityController {
  constructor(private readonly securityService: SecurityService) {}

  @TwoFactorAuthSwaggerDocs()
  @Patch('two-factor-auth')
  async toggleTwoFactorAuth(
    @Req() req: RequestWithId,
    @Body() { visitorId }: VisitorIdDTO,
  ) {
    return this.securityService.toggleTwoFactorAuth(req, visitorId);
  }
}
