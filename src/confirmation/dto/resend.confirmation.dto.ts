import { PickType } from '@nestjs/swagger';
import VerifyConfirmationDTO from './verify.confirmation.dto';

export default class ResendConfirmationDTO extends PickType(VerifyConfirmationDTO, [
  'confirmationId',
] as const) {}
