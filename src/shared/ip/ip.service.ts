import { Injectable, Logger } from '@nestjs/common';
import * as net from 'net';
import type RequestWithId from 'src/common/entities/IRequestWithId';
import { BcryptService } from '../bcrypt/bcrypt.service';
import { PROXY_HEADERS } from 'src/common/globals';

@Injectable()
export class IPService {
  private readonly logger = new Logger(IPService.name, {
    timestamp: true,
  });

  constructor(private readonly bcryptService: BcryptService) {}

  // Get hashed country by ip address
  async getCountryByIp(
    req: RequestWithId,
    hashed: boolean = false,
  ): Promise<string | null> {
    const ip: string | null = this.getClientIp(req);
    const country = ip ? await this.fetchCountryByIP(ip) : null;

    if (!country) {
      return null;
    }

    return hashed ? await this.bcryptService.hash(country) : country;
  }

  // Get country by ip address
  private async fetchCountryByIP(ip: string): Promise<string | null> {
    try {
      const res = await fetch(
        `http://ip-api.com/json/${ip}?fields=status,message,country,query,city,lat,lon,timezone,regionName,continent,isp,org,as,asname,mobile,proxy,hosting`,
      );
      const json = await res.json();

      if (!res.ok || json.status === 'fail') {
        this.logger.error(
          `Failed to fetch user's country by ip. ${
            json.status === 'fail'
              ? `Error message: ${json.message}, query:${json.query}`
              : ''
          }`,
        );
        return null;
      }

      return json.country;
    } catch (error) {
      this.logger.error(
        `Error requesting IP geolocation: ${(error as Error).message}`,
      );
      return null;
    }
  }

  private getClientIp(req: RequestWithId | null | undefined): string | null {
    if (!req || typeof req !== 'object') {
      return null;
    }

    const headers = req.headers;

    if (headers && typeof headers === 'object') {
      const xClientIp = headers['x-client-ip'];
      const rawClientIp = Array.isArray(xClientIp) ? xClientIp[0] : xClientIp;
      if (this.isIp(rawClientIp)) {
        return rawClientIp;
      }

      const xForwardedFor = headers['x-forwarded-for'];
      const rawForwardedFor = Array.isArray(xForwardedFor)
        ? xForwardedFor[0]
        : xForwardedFor;
      const ipFromForwarded =
        this.getClientIpFromXForwardedFor(rawForwardedFor);
      if (this.isIp(ipFromForwarded)) {
        return ipFromForwarded;
      }

      for (const headerName of PROXY_HEADERS) {
        const headerVal = headers[headerName.toLowerCase()];
        const singleVal = Array.isArray(headerVal) ? headerVal[0] : headerVal;

        if (this.isIp(singleVal)) {
          return singleVal;
        }
      }
    }

    const connectionCandidates: (string | undefined)[] = [
      (req as any).connection?.remoteAddress,
      (req as any).connection?.socket?.remoteAddress,
      req.socket?.remoteAddress,
      (req as any).info?.remoteAddress,
      (req as any).requestContext?.identity?.sourceIp,
    ];

    for (const candidate of connectionCandidates) {
      if (this.isIp(candidate)) {
        return candidate;
      }
    }

    if ((req as any).raw) {
      return this.getClientIp((req as any).raw);
    }

    return null;
  }

  private getClientIpFromXForwardedFor(value: unknown): string | null {
    if (typeof value !== 'string') {
      return null;
    }

    for (const part of value.split(',')) {
      const candidate = this.cleanIp(part);
      if (this.isIp(candidate)) {
        return candidate;
      }
    }

    return null;
  }

  private cleanIp(rawIp: string): string {
    const ip = rawIp.trim();

    const ipv6WithPortMatch = ip.match(/^\[(.*)\]:\d+$/);
    if (ipv6WithPortMatch) {
      return ipv6WithPortMatch[1];
    }

    if (ip.includes(':') && ip.indexOf(':') === ip.lastIndexOf(':')) {
      return ip.split(':')[0];
    }

    return ip;
  }

  private isIp(value: unknown): value is string {
    if (typeof value !== 'string') {
      return false;
    }

    if (
      value === '::1' ||
      value === '127.0.0.1' ||
      value === '::ffff:127.0.0.1'
    ) {
      return false;
    }

    return net.isIP(value) !== 0;
  }
}
