import {
  BadGatewayException,
  Inject,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { PrismaService } from 'src/prisma-database/prisma.service';
import RequestWithId from 'src/common/entities/IRequestWithId';
import { User } from 'generated/prisma';
import { ConfirmationService } from 'src/confirmation/confirmation.service';
import {
  FAILED_LOGIN_ATTEMPTS_CONFIG,
  LETTER_TEMPLATES,
  RISK_BASED_AUTH_CONFIG,
} from 'src/common/globals';
import { IPService } from 'src/shared/ip/ip.service';

@Injectable()
export class SecurityService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly confirmationService: ConfirmationService,
    private readonly ipService: IPService,
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
  ) {}

  // Record failed sign-in attempt
  async recordFailedLoginAttempt(userId: string): Promise<void> {
    const key = `failed_attempts:${userId}`;
    const current = (await this.cacheManager.get<number>(key)) || 0;
    await this.cacheManager.set(
      key,
      current + 1,
      FAILED_LOGIN_ATTEMPTS_CONFIG.LOCKOUT_DURATION,
    );
  }

  // Reset attempt counter after successful sign-in
  async clearFailedLoginAttempts(userId: string): Promise<void> {
    await this.cacheManager.del(`failed_attempts:${userId}`);
  }

  // Enable/Disable Two Factor Authentication for user
  async toggleTwoFactorAuth(req: RequestWithId): Promise<{ message: string }> {
    const { id, visitorId } = req;
    const user = await this.findUserById(id); // Find user by id
    const twoFactorAuthEnabled = user.twoFactorAuthEnabled;

    await this.prismaService
      .$transaction(async (tx) => {
        const updatedUser = await tx.user.update({
          where: { id },
          data: {
            twoFactorAuthEnabled: !twoFactorAuthEnabled,
          },
        });

        if (updatedUser.twoFactorAuthEnabled) {
          const ipInfo = await this.ipService.getInfoFromIp(req);
          if (ipInfo) {
            await tx.authLog.create({
              data: { userId: id, ...ipInfo },
            });
          }

          if (visitorId) {
            const existingDevice = await tx.trustedDevice.findFirst({
              where: { userId: id, visitorId },
            });
            if (!existingDevice) {
              await tx.trustedDevice.create({
                data: { userId: id, visitorId },
              });
            }
          }
        } else {
          await tx.authLog.deleteMany({ where: { userId: id } });
          await tx.trustedDevice.deleteMany({ where: { userId: id } });
        }
      })
      .catch((error) => {
        throw new BadGatewayException(
          `Failed to toggle two-factor authentication: ${error.message}`,
        );
      });

    return {
      message: `Two-factor authentication has been successfully ${twoFactorAuthEnabled ? 'disabled' : 'enabled'}`,
    };
  }

  // Risk-based adaptive 2FA verification
  async twoFactorAuth(
    user: User,
    req: RequestWithId,
  ): Promise<true | { message: string; confirmationId: string }> {
    const visitorId =
      req.visitorId || (req.headers['x-visitor-id'] as string) || null;

    const ipInfo = await this.ipService.getInfoFromIp(req);

    const [trustedDevices, authLogs] = await Promise.all([
      this.prismaService.trustedDevice.findMany({
        where: { userId: user.id },
      }),
      this.prismaService.authLog.findMany({
        where: { userId: user.id },
        orderBy: { createdAt: 'desc' },
      }),
    ]);

    let riskScore = 0;

    // 1. Device check (Browser Fingerprint)
    let isDeviceTrusted = false;
    if (visitorId && trustedDevices.length > 0) {
      for (const dev of trustedDevices) {
        if (dev.visitorId === visitorId) {
          isDeviceTrusted = true;
          break;
        }
      }
    }

    if (!isDeviceTrusted) {
      riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.VISITOR_ID_MISMATCH; 
    }

    // 2. IP & Geolocation Analysis
    if (ipInfo) {
      // 2.1 Impossible Travel Check
      if (authLogs.length > 0 && ipInfo.lat != null && ipInfo.lon != null) {
        const latestLog = authLogs[0];
        if (latestLog.lat != null && latestLog.lon != null) {
          const timeDiffHours =
            (Date.now() - new Date(latestLog.createdAt).getTime()) /
            (1000 * 60 * 60);
          const minIntervalHours =
            RISK_BASED_AUTH_CONFIG.VELOCITY_LIMITS.MIN_TIME_INTERVAL_SECONDS /
            3600;

          if (timeDiffHours >= minIntervalHours) {
            const distanceKm = this.calculateHaversineDistance(
              latestLog.lat,
              latestLog.lon,
              ipInfo.lat,
              ipInfo.lon,
            );
            const speedKmh = distanceKm / timeDiffHours;
            if (
              speedKmh >
              RISK_BASED_AUTH_CONFIG.VELOCITY_LIMITS.MAX_REALISTIC_SPEED_KMH
            ) {
              riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.IMPOSSIBLE_TRAVEL; 
            }
          }
        }
      }

      // 2.2 Continent Check
      if (authLogs.length > 0 && ipInfo.continent) {
        const knownContinent = authLogs.some(
          (log) =>
            log.continent?.toLowerCase() === ipInfo.continent?.toLowerCase(),
        );
        if (!knownContinent) {
          riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.NEW_CONTINENT; 
        }
      }

      // 2.3 Country & City Check
      if (authLogs.length > 0 && ipInfo.country) {
        const knownCountry = authLogs.some(
          (log) => log.country?.toLowerCase() === ipInfo.country?.toLowerCase(),
        );
        if (!knownCountry) {
          riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.NEW_COUNTRY; 
        } else {
          // If country is recognized — verify city and region
          if (ipInfo.city) {
            const knownCity = authLogs.some(
              (log) => log.city?.toLowerCase() === ipInfo.city?.toLowerCase(),
            );
            if (!knownCity) {
              riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.NEW_CITY; 
            }
          }
          if (ipInfo.regionName) {
            const knownRegion = authLogs.some(
              (log) =>
                log.regionName?.toLowerCase() ===
                ipInfo.regionName?.toLowerCase(),
            );
            if (!knownRegion) {
              riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.NEW_REGION; 
            }
          }
        }
      }

      // 2.4 Network Anomalies (VPN, Proxy, Data Center)
      if (ipInfo.proxy) {
        riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.VPN_OR_PROXY_DETECTED; 
      }
      if (ipInfo.hosting) {
        riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.DATA_CENTER_IP; 
      }

      // 2.5 Change in ISP or Autonomous System (ASN)
      if (authLogs.length > 0 && (ipInfo.as || ipInfo.isp)) {
        const knownNetwork = authLogs.some(
          (log) =>
            (ipInfo.as && log.as === ipInfo.as) ||
            (ipInfo.isp && log.isp === ipInfo.isp),
        );
        if (!knownNetwork) {
          riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.NEW_ASN_OR_ISP; 
        }
      }
    }

    // 3. Timezone Mismatch Check
    const clientTimezone =
      (req.headers['x-timezone'] as string) ||
      (req.headers['x-client-timezone'] as string) ||
      null;

    if (ipInfo?.timezone) {
      if (clientTimezone) {
        if (
          clientTimezone.trim().toLowerCase() !==
          ipInfo.timezone.trim().toLowerCase()
        ) {
          riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.TIMEZONE_MISMATCH; 
        }
      } else if (authLogs.length > 0) {
        const knownTimezone = authLogs.some(
          (log) =>
            log.timezone?.toLowerCase() === ipInfo.timezone.toLowerCase(),
        );
        if (!knownTimezone) {
          riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.TIMEZONE_MISMATCH; 
        }
      }
    }

    // 4. Unusual Login Time Check
    if (authLogs.length >= 3) {
      const currentLocalHour = this.getHourInTimezone(
        new Date(),
        ipInfo?.timezone || undefined,
      );

      const historicalHours = authLogs.map((log) =>
        this.getHourInTimezone(
          new Date(log.createdAt),
          log.timezone || undefined,
        ),
      );

      // Minimum circular distance on a 24-hour clock face
      const minDistance = Math.min(
        ...historicalHours.map((h) => {
          const diff = Math.abs(currentLocalHour - h);
          return Math.min(diff, 24 - diff);
        }),
      );

      const isDeepNight = currentLocalHour >= 1 && currentLocalHour <= 5;
      const hasNightHistory = historicalHours.some((h) => h >= 1 && h <= 5);

      if (minDistance >= 4 || (isDeepNight && !hasNightHistory)) {
        riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.UNUSUAL_LOGIN_TIME;
      }
    }

    // 5. Failed Attempts Burst Check
    const failedAttempts =
      (await this.cacheManager.get<number>(`failed_attempts:${user.id}`)) || 0;
    if (failedAttempts >= FAILED_LOGIN_ATTEMPTS_CONFIG.MAX_ATTEMPTS) {
      riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.FAILED_ATTEMPTS_BURST;
    }

    // 6. Decision Making: If the risk score exceeds the security threshold - trigger 2FA
    if (riskScore > RISK_BASED_AUTH_CONFIG.THRESHOLDS.LOW_RISK_MAX) {
      return this.sendTwoFactorAuthConfirmation(user.id, user.email);
    }

    // 7. Low Risk: Update the IP record in AuthLog
    if (ipInfo) {
      await this.prismaService.authLog
        .upsert({
          where: {
            userId_ip: {
              userId: user.id,
              ip: ipInfo.ip,
            },
          },
          update: { ...ipInfo },
          create: { userId: user.id, ...ipInfo },
        })
        .catch(() => null);
    }

    return true;
  }

  // Calculate hour adjusted for timezone
  private getHourInTimezone(date: Date, timezone?: string): number {
    if (timezone) {
      try {
        const parts = new Intl.DateTimeFormat('en-US', {
          timeZone: timezone,
          hour: 'numeric',
          hourCycle: 'h23',
        }).formatToParts(date);
        const hourPart = parts.find((p) => p.type === 'hour');
        if (hourPart) return parseInt(hourPart.value, 10);
      } catch {
        // Fallback to local time if timezone identifier validation fails
      }
    }
    return date.getHours();
  }

  // Distance Calculation using the Haversine Formula (in km)
  private calculateHaversineDistance(
    lat1: number,
    lon1: number,
    lat2: number,
    lon2: number,
  ): number {
    const R = 6371;
    const dLat = ((lat2 - lat1) * Math.PI) / 180;
    const dLon = ((lon2 - lon1) * Math.PI) / 180;
    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos((lat1 * Math.PI) / 180) *
        Math.cos((lat2 * Math.PI) / 180) *
        Math.sin(dLon / 2) *
        Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
  }

  // Create confirmation record and send confirmation letter via email
  private async sendTwoFactorAuthConfirmation(
    userId: string,
    email: string,
  ): Promise<{
    message: string;
    confirmationId: string;
  }> {
    // Check if the confirmation has already been requested
    const existingConfirmation =
      await this.prismaService.confirmation.findFirst({
        where: { userId, type: 'TWO_FACTOR_AUTH' },
      });

    // If confirmation has already been requested, resend it; if not, create and send a new confirmation
    const confirmationId = existingConfirmation
      ? await this.confirmationService.resendConfirmation(
          existingConfirmation.id,
        )
      : await this.confirmationService.createAndSendConfirmation({
          userId,
          type: 'TWO_FACTOR_AUTH',
          email,
          customerName: 'Dear Client',
          subject: LETTER_TEMPLATES.TWO_FACTOR_AUTH.subject,
          TemplateID: LETTER_TEMPLATES.TWO_FACTOR_AUTH.id,
        });

    return {
      message:
        'Suspicious activity detected. A verification code has been sent to your email. Please check your inbox and enter the code to proceed',
      confirmationId:
        typeof confirmationId === 'string'
          ? confirmationId
          : confirmationId.confirmationId,
    };
  }

  // Get user by id
  private async findUserById(id: string): Promise<User> {
    const user = await this.prismaService.user.findUnique({ where: { id } });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }
}
