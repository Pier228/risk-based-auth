import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';

@Injectable()
export class BcryptService {
  constructor(private readonly configService: ConfigService) {}

  // Hash string via bcrypt
  async hash(text: string): Promise<string> {
    return bcrypt.hash(
      text,
      Number(this.configService.get('SALT_ROUNDS') || 12),
    );
  }

  // Compare plain text with encrypted text
  async compare(text: string, encrypted: string): Promise<boolean> {
    return bcrypt.compare(text, encrypted);
  }
}
