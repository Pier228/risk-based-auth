import {
  BadGatewayException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma-database/prisma.service';
import RequestWithId from 'src/common/entities/IRequestWithId';
import { User } from 'generated/prisma';
import { ConfirmationService } from 'src/confirmation/confirmation.service';
import { LETTER_TEMPLATES, RISK_BASED_AUTH_CONFIG } from 'src/common/globals';
import { IPService } from 'src/shared/ip/ip.service';

@Injectable()
export class SecurityService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly confirmationService: ConfirmationService,
    private readonly ipService: IPService,
  ) {}

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
      (req as RequestWithId).visitorId ||
      (req.headers['x-visitor-id'] as string) ||
      null;

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

    // Browser Fingerprint
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
      riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.VISITOR_ID_MISMATCH; // +30
    }

    // 2. IP & Geolocation Analysis
    if (ipInfo) {
      // 2.1 Impossible Travel Check against the Last Recorded Sign-In
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
              riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.IMPOSSIBLE_TRAVEL; // +100
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
          riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.NEW_CONTINENT; // +40
        }
      }

      // 2.3 Country and City Check
      if (authLogs.length > 0 && ipInfo.country) {
        const knownCountry = authLogs.some(
          (log) => log.country?.toLowerCase() === ipInfo.country?.toLowerCase(),
        );
        if (!knownCountry) {
          riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.NEW_COUNTRY; // +35
        } else {
          // If country is recognized — verify city and region
          if (ipInfo.city) {
            const knownCity = authLogs.some(
              (log) => log.city?.toLowerCase() === ipInfo.city?.toLowerCase(),
            );
            if (!knownCity) {
              riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.NEW_CITY; // +15
            }
          }
          if (ipInfo.regionName) {
            const knownRegion = authLogs.some(
              (log) =>
                log.regionName?.toLowerCase() ===
                ipInfo.regionName?.toLowerCase(),
            );
            if (!knownRegion) {
              riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.NEW_REGION; // +10
            }
          }
        }
      }

      // 2.4 Network Anomalies (VPN, Proxy, Data Center)
      if (ipInfo.proxy) {
        riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.VPN_OR_PROXY_DETECTED; // +30
      }
      if (ipInfo.hosting) {
        riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.DATA_CENTER_IP; // +40
      }

      // 2.5 Change in ISP or Autonomous System (ASN)
      if (authLogs.length > 0 && (ipInfo.as || ipInfo.isp)) {
        const knownNetwork = authLogs.some(
          (log) =>
            (ipInfo.as && log.as === ipInfo.as) ||
            (ipInfo.isp && log.isp === ipInfo.isp),
        );
        if (!knownNetwork) {
          riskScore += RISK_BASED_AUTH_CONFIG.PENALTIES.NEW_ASN_OR_ISP; // +15
        }
      }
    }

    // 3. Decision Making: If the risk score exceeds the security threshold - trigger 2FA
    if (riskScore > RISK_BASED_AUTH_CONFIG.THRESHOLDS.LOW_RISK_MAX) {
      return this.sendTwoFactorAuthConfirmation(user.id, user.email);
    }

    // 4. Low Risk: Update the IP record in AuthLog
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
