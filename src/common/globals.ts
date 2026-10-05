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
