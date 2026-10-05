import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { UNCONFIRMED_ACCOUNTS_CLEANUP } from 'src/common/globals';
import { PrismaService } from 'src/prisma-database/prisma.service';

@Injectable()
export class CleanupService {
  constructor(private readonly prisma: PrismaService) {}
  private readonly logger = new Logger(CleanupService.name);

  // Delete all expired refresh token
  @Cron(CronExpression.EVERY_DAY_AT_4AM) // Every day at 4:00 am
  async handleTokenCleanup() {
    const { count } = await this.prisma.token.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    });

    this.logger.log(`Removed expired refresh tokens: ${count}`);
  }

  // Delete all users with unconfirmed emails
  @Cron(CronExpression.EVERY_DAY_AT_3AM) // Every day at 3:00 am
  async handleUnconfirmedAccountsCleanup() {
    const { count } = await this.prisma.user.deleteMany({
      where: {
        emailConfirmed: false,
        createdAt: { lt: new Date(Date.now() - UNCONFIRMED_ACCOUNTS_CLEANUP) },
      },
    });

    this.logger.log(`Removed unconfirmed users: ${count}`);
  }
}
