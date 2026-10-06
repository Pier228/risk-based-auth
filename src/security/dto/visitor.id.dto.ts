import { IsNotEmpty, IsString, MinLength } from 'class-validator';

export default class VisitorIdDTO {
  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  visitorId: string;
}
