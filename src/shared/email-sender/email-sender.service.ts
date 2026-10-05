import { BadGatewayException, Injectable } from '@nestjs/common';
import type ISendEmail from './entities/ISendEmail';
import { ConfigService } from '@nestjs/config';

const Mailjet = require('node-mailjet');

@Injectable()
export class EmailSenderService {
  private readonly mailjet;

  constructor(private readonly configService: ConfigService) {
    this.mailjet = Mailjet.apiConnect(
      this.configService.getOrThrow('MAILJET_API_KEY'),
      this.configService.getOrThrow('MAILJET_SECRET_KEY'),
    );
  }

  async sendEmail({
    senderEmail,
    senderName,
    customerEmail,
    customerName,
    subject,
    ...letter
  }: ISendEmail): Promise<{ message: string; response: any }> {
    try {
      const response = await this.mailjet
        .post('send', { version: 'v3.1' })
        .request({
          Messages: [
            {
              From: {
                Email: senderEmail,
                Name: senderName,
              },
              To: [
                {
                  Email: customerEmail,
                  Name: customerName,
                },
              ],
              Subject: subject,
              TemplateLanguage: letter.templateLetter ? true : false,
              ...(letter.templateLetter || letter.textLetter),
            },
          ],
        });

      return { message: 'Email has been sent', response: response.body };
    } catch (error) {
      throw new BadGatewayException('Failed to send email');
    }
  }
}
