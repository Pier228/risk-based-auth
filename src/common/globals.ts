import { CookieOptions } from 'express';
import type ISendEmail from 'src/shared/email-sender/entities/ISendEmail';

export const USER_CONFIG = {
  // User configuration, which is used in DTO
  PASSWORD: {
    minLength: 8,
    maxLength: 30,
  },
  NAME: {
    minLength: 2,
    maxLength: 20,
  },
  SURNAME: {
    minLength: 2,
    maxLength: 20,
  },
};

export const ACCESS_TOKEN_CONFIG = {
  EXPIRES_IN: '15m', // Access token expiration time - 15 minutes
  MAX_AGE: 15 * 60 * 1000, // 15 minutes in milliseconds
};

export const REFRESH_TOKEN_CONFIG = {
  EXPIRES_IN: '7d', // Refresh token expiration time - 7 days
  MAX_AGE: 1000 * 60 * 60 * 24 * 7, // 7 days in milliseconds
};

export const FAILED_LOGIN_ATTEMPTS_CONFIG = {
  MAX_ATTEMPTS: 3, // Maximum failed login attempts 
  LOCKOUT_DURATION: 10 * 60 * 1000, // Lockout duration in milliseconds (10 minutes)
};

export const getCookieConfig = (maxAge: number): CookieOptions => ({
  httpOnly: true, // Prevents client-side JavaScript from accessing the cookie
  secure: true, // Ensures cookies are only sent over HTTPS connections
  sameSite: 'lax', // CSRF protection: 'lax' allows safe top-level navigation cookies
  signed: true, // Enables cookie signing to prevent tampering
  maxAge, // Sets cookie expiration (in milliseconds)
});

export const CONFIRMATION_CONFIG = {
  VERIFICATION_TIME: 15 * 60 * 1000, // 15 minutes in milliseconds
  get RESEND_THRESHOLD() {
    return this.VERIFICATION_TIME / 3; // 5 minutes in milliseconds
  },
};

export const LETTERS_CONFIG: Pick<ISendEmail, 'senderEmail' | 'senderName'> = {
  senderEmail: process.env.MAILJET_SENDER_EMAIL,
  senderName: 'Support Team',
};

export const LETTER_TEMPLATES = {
  EMAIL_VERIFICATION: {
    id: 8404990, // Confirmation email template ID - must contain token variable
    subject: 'Confirm Your Email Address',
  },
  TWO_FACTOR_AUTH: { id: 8405258, subject: 'Confirm Your Sign-In' },
  CONFIRMATION_TEMPLATE_ID: { id: 8405271, subject: 'Your verification code' }, // Universal confirmation template
};

// Time after which unconfirmed accounts should be deleted
export const UNCONFIRMED_ACCOUNTS_CLEANUP = 2 * 24 * 60 * 60 * 1000; // 2 days in milliseconds

export enum BLACK_LIST_REASONS {
  SIGN_OUT = 'sign_out',
  SUSPICIOUS_ACTIVITY = 'suspicious_activity',
  ADMIN_INVALIDATE = 'admin_invalidate',
}

export const PROXY_HEADERS: readonly string[] = [
  'x-client-ip',
  'cf-connecting-ip',
  'fastly-client-ip',
  'true-client-ip',
  'x-real-ip',
  'x-cluster-client-ip',
  'x-forwarded',
  'forwarded-for',
  'forwarded',
  'x-appengine-user-ip',
  'cf-pseudo-ipv4',
];

export const RISK_BASED_AUTH_CONFIG = {
  THRESHOLDS: {
    LOW_RISK_MAX: 29, // 0-29: Allow sign-in without 2FA
    MEDIUM_RISK_MAX: 74, // 30-74: Require step-up authentication
    HIGH_RISK_MIN: 75, // >= 75: Critical risk; block attempt and trigger alert
  },

  // Penalty scores for detected anomalies
  PENALTIES: {
    // 1. Device anomalies (Browser Fingerprinting)
    VISITOR_ID_MISMATCH: 30, // visitorId from FingerprintJS

    // 2. Geographic anomalies
    NEW_COUNTRY: 35, // Sign-in from a country not previously recorded in history
    NEW_CITY: 10, // New city within the same country
    NEW_REGION: 15, // New region/state within the same country
    NEW_CONTINENT: 40, // Sign-in from a continent not previously recorded in history
    IMPOSSIBLE_TRAVEL: 100, // Physically impossible travel velocity between locations

    // 3. Network anomalies
    VPN_OR_PROXY_DETECTED: 30, // Public VPN, proxy, or Tor exit node detected
    DATA_CENTER_IP: 40, // IP belongs to a hosting provider or data center (AWS, DigitalOcean, etc.)
    NEW_ASN_OR_ISP: 15, // Change in autonomous system (ASN) or Internet service provider (ISP)

    // 4. Temporal and behavioral factors
    TIMEZONE_MISMATCH: 15, // Discrepancy between system timezone and IP-resolved timezone
    UNUSUAL_LOGIN_TIME: 10, // Sign-in at an atypical time of day for the user (e.g., late night)
    FAILED_ATTEMPTS_BURST: 20, // Burst of recent failed sign-in attempts within a short window
  },

  // Velocity parameters for impossible travel detection
  VELOCITY_LIMITS: {
    MAX_REALISTIC_SPEED_KMH: 900, // Maximum realistic travel speed (km/h, commercial airliner)
    MIN_TIME_INTERVAL_SECONDS: 60, // Minimum time delta between events to avoid division by zero
  },
};
