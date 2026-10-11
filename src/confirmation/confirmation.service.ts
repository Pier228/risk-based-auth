import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma-database/prisma.service';
import { Confirmation, ConfirmationType, Prisma } from 'generated/prisma';
import { EmailSenderService } from 'src/shared/email-sender/email-sender.service';
import type ICreateConfirmation from './entities/ICreateConfirmation';
import VerifyConfirmationDTO from './dto/verify.confirmation.dto';
import { Response } from 'express';
import { PostConfirmationService } from './post-confirmation.service';
import {
  CONFIRMATION_CONFIG,
  LETTER_TEMPLATES,
  LETTERS_CONFIG,
} from 'src/common/globals';
import type ICreateAndSendConfirmation from './entities/ICreateAndSendConfirmation';
import { BcryptService } from 'src/shared/bcrypt/bcrypt.service';
import type RequestWithId from 'src/common/entities/IRequestWithId';

@Injectable()
export class ConfirmationService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly emailSenderService: EmailSenderService,
    private readonly postConfirmationService: PostConfirmationService,
    private readonly bcryptService: BcryptService,
  ) {}

  // Verify confirmation and run the post-confirmation function
  async handleConfirmation(
    { confirmationId, token }: VerifyConfirmationDTO,
    response: Response,
    request: RequestWithId,
  ) {
    return this.prisma.$transaction(async (tx) => {
      // Verify confirmation
      const { userId, type } = await this.verifyConfirmationCode(
        confirmationId,
        token,
        tx,
      );

      // Run post-confirmation functions
      switch (type) {
        case 'EMAIL_VERIFICATION':
          return this.postConfirmationService.handleEmailVerification(
            userId,
            response,
            tx,
          );

        case 'TWO_FACTOR_AUTH':
          return this.postConfirmationService.handleTwoFactorAuthorization(
            userId,
            response,
            request,
            tx,
          );

        default:
          throw new InternalServerErrorException(
            `Unsupported confirmation type: ${type}`,
          );
      }
    });
  }

  // Resend email confirmation letter
  async resendConfirmation(
    confirmationId: string,
  ): Promise<Record<string, string>> {
    const confirmation = await this.prisma.confirmation.findFirst({
      where: { id: confirmationId },
      include: {
        user: {
          include: {
            Profile: { select: { name: true, surname: true } },
          },
        },
      },
    });

    if (!confirmation) {
      throw new NotFoundException('Confirmation record not found');
    }

    this.checkEmailResendEligibility(confirmation.createdAt); // Check if the resend is allowed

    const [user, profile] = [confirmation.user, confirmation.user.Profile];

    const newConfirmationId = await this.prisma.$transaction(async (tx) => {
      // Delete old confirmation
      await tx.confirmation.delete({
        where: { id: confirmation.id },
      });

      const customerName = profile.name + ' ' + profile.surname;
      const letterTemplate = LETTER_TEMPLATES[confirmation.type];

      // Create new confirmation & send confirmation email
      return this.createAndSendConfirmation({
        userId: user.id,
        email: user.email,
        customerName,
        type: confirmation.type,
        tx,
        subject: letterTemplate?.subject,
        TemplateID: letterTemplate?.id,
      });
    });

    return {
      message: 'Confirmation letter has been successfully sent',
      confirmationId: newConfirmationId,
    };
  }

  // Create a new confirmation and send a confirmation letter via email.
  async createAndSendConfirmation({
    userId,
    type,
    tx,
    email,
    customerName,
    subject,
    variables,
    TemplateID,
  }: ICreateAndSendConfirmation): Promise<string> {
    const { token, confirmation } = await this.createConfirmation({
      userId,
      type,
      tx,
      expiresIn: CONFIRMATION_CONFIG.VERIFICATION_TIME,
    });

    // Send confirmation email
    await this.emailSenderService.sendEmail({
      ...LETTERS_CONFIG,
      customerEmail: email,
      customerName,
      subject: subject ?? LETTER_TEMPLATES.CONFIRMATION_TEMPLATE_ID.subject,
      templateLetter: {
        TemplateID: TemplateID ?? LETTER_TEMPLATES.CONFIRMATION_TEMPLATE_ID.id,
        Variables: { token, ...(variables ?? {}) },
      },
    });

    return confirmation.id;
  }

  // Create new confirmation
  private async createConfirmation({
    tx,
    expiresIn,
    ...confirmationData
  }: ICreateConfirmation): Promise<{
    token: string;
    confirmation: Confirmation;
  }> {
    const token = this.generateToken(); // Generate token

    // Hash the password using bcrypt
    const hashedToken = await this.bcryptService.hash(token);
    const prisma = tx ?? this.prisma; // Use tx(transaction prisma model) or prismaService

    // Create confirmation record
    const confirmation = await prisma.confirmation.create({
      data: {
        ...confirmationData,
        token: hashedToken,
        expiresAt: new Date(Date.now() + expiresIn),
      },
    });

    return { token, confirmation };
  }

  // Verify confirmation and delete it
  private async verifyConfirmationCode(
    id: string,
    token: string,
    tx?: Prisma.TransactionClient,
  ): Promise<{ userId: string; type: ConfirmationType }> {
    const prisma = tx ?? this.prisma; // Use tx(transaction prisma model) or prismaService
    const confirmation = await prisma.confirmation.findFirst({
      where: { id },
    });

    if (
      !confirmation ||
      !(await this.bcryptService.compare(token, confirmation.token))
    ) {
      throw new UnauthorizedException(
        'A confirmation record was not found, or the wrong token was provided',
      );
    }

    if (confirmation.expiresAt < new Date()) {
      throw new UnauthorizedException('Token expired');
    }

    return prisma.confirmation.delete({
      where: { id: confirmation.id },
      select: { userId: true, type: true },
    });
  }

  // Generates a 6-digit number code
  private generateToken(): string {
    return (Math.floor(Math.random() * 900000) + 100000).toString();
  }

  // Check if the resend is allowed
  private checkEmailResendEligibility(createdAt: Date): void {
    const now = Date.now();
    const timeSinceCreation = now - createdAt.getTime(); // Calculate time since confirmation creation

    // Check if the confirmation isn't allowed
    if (timeSinceCreation < CONFIRMATION_CONFIG.RESEND_THRESHOLD) {
      const msRemaining =
        CONFIRMATION_CONFIG.RESEND_THRESHOLD - timeSinceCreation; // Calculate remaining time to send confirmation letter again in milliseconds
      const secondsRemaining = Math.ceil(msRemaining / 1000); // Covert remaining time to seconds
      const minutesRemaining = Math.round((secondsRemaining / 60) * 100) / 100; // Covert remaining time to minutes
      const retryAt = new Date(now + msRemaining); // Calculate the time when the user will be allowed to request a confirmation letter again

      throw new BadRequestException({
        message: 'Please wait a bit before requesting again.',
        statusCode: 400,
        error: 'Bad Request',
        secondsRemaining,
        minutesRemaining,
        retryAt,
      });
    }
  }
}
