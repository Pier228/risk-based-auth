<p align="center">
  <img src="https://i.imgur.com/zRd6TnI.png" width="300" alt="Second Level Logo" />
</p>

# Level 3 – Advanced Token Protection

This level introduces an **advanced security layer** that builds upon previous authentication strategies by integrating **token invalidation**, **contextual validation**, and optional **Two-Factor Authentication (2FA)**. Its primary goal is to prevent unauthorized reuse of tokens—particularly after logout—and to enhance account security through **geographic login analysis** and **device fingerprinting**.

Key enhancements include:

- **Access token blocklisting** to ensure tokens cannot be reused after logout
- **IP-based country detection during login**, triggering 2FA if a login attempt occurs from a different country
- **User-Agent binding for refresh tokens**, used to verify consistency during token renewal
- **Optional 2FA** that is triggered only when unusual login behavior is detected
- A flexible **caching layer** (e.g., Redis or in-memory) for efficient storage and lookup of invalidated access tokens

These improvements address key security gaps in standard JWT flows by introducing **context-awareness** and **token lifecycle control**, while preserving the benefits of a stateless, scalable architecture. This level is ideal for applications that demand **stronger safeguards** without relying on fully stateful session models or external identity providers.

## Table of Contents

- [Description](#description)
- [New Features](#new-features)
- [Features from previous levels](#features-from-previous-levels)
- [Tech Stack](#tech-stack)
- [Database Structure](#database-structure)
- [How It Works: General](#how-it-works-general)
- [How It Works: 2FA](#how-it-works-two-factor-authentication-2fa)
- [Endpoints](#endpoints)
- [Example Request](#example-request)
- [Configurations](#configurations)
  - [Cookie](#cookie)
  - [Confirmation](#confirmation)
  - [Letters](#letters)
- [Security Improvements](#security-improvements-over-level-2)
- [Security Notes](#security-notes)
- [Testing](#testing)
- [Installation](#installation)
  - [GitHub](#github)
  - [Docker Image](#docker-image)
- [Environment Variables](#environment-variables)
- [Running the App](#running-the-app)
- [License](#license)

## Description

This level significantly enhances the security of JWT-based authentication by combining **token lifecycle control**, **environment-aware validation**, and **optional Two-Factor Authentication (2FA)**. The core objective is to ensure that access tokens cannot be reused after logout, and that refresh tokens are tied to specific user contexts—such as browser and location—making unauthorized access significantly harder.

Here's a high-level overview of what this level introduces:

- **Access Token Blocklist**: When a user logs out, their access token is immediately added to a blocklist (stored in Redis or in-memory cache) and becomes unusable even if it hasn't yet expired.

- **Refresh Token User-Agent Binding**: Each refresh token is bound to the User-Agent that was used during its issuance. When a user attempts to exchange a refresh token for a new access token, the current User-Agent is validated against the stored (hashed) one to detect anomalies or token theft.

- **Login Country Verification**: On sign-in, the user's IP is used to determine their country. If the country differs from previous logins (and 2FA is enabled), the system requires the user to verify the login via a one-time email confirmation code.

- **Two-Factor Authentication (2FA)**: Users can enable 2FA to strengthen account protection. When enabled, geographic inconsistency (based on IP-to-country lookup) will trigger an additional email verification step before access is granted.

- **Smart Cleanup**: Refresh tokens are deleted from the database upon logout. Access tokens are added to a time-bound cache (with TTL matching the token’s remaining validity), ensuring they are rejected for the rest of their lifespan.

This level aims to preserve the **statelessness and scalability** of token-based auth systems, while introducing **dynamic runtime validation** and **security context awareness** — two critical elements often lacking in traditional JWT implementations.

## New Features

This level introduces several powerful features aimed at **tightening security** and **improving control** over token usage. These additions build upon the previous levels and are designed to prevent unauthorized access, reuse of credentials, and session hijacking.

### Access Token Blocklist

- Access tokens are now actively invalidated on logout.
- A **caching layer** (Redis or in-memory) stores invalidated tokens with a TTL equal to their remaining lifespan.
- Incoming requests are checked against the blocklist to **prevent reuse** of logged-out tokens.

### Refresh Token User-Agent Binding

- Every refresh token is bound to the **User-Agent** (browser/device signature) at the moment of issuance.
- The User-Agent is securely hashed and stored alongside the token.
- When exchanging a refresh token for a new access token, the system validates that the current User-Agent matches the stored one.
- Prevents stolen tokens from being reused on unauthorized devices.

### Context-Aware Sign-In with Country Verification

- On sign-in, the user's **IP address** is used to infer their **geographic location (country)**.
- If 2FA is enabled and the detected country differs from the previously stored one:

  - A confirmation email is sent with a **6-digit verification code**.
  - Access is granted **only after successful confirmation**.

- Prevents unauthorized logins from unexpected locations.

### Optional Two-Factor Authentication (2FA)

- Users can **opt-in** to use 2FA for added protection.
- When enabled:

  - **Sign-in from a new country** triggers an extra verification step:

    - User’s IP address is mapped to a country.
    - If it differs from the previously confirmed one, access is paused.
    - A **6-digit confirmation code** is sent to the user’s email.
    - Access is granted only after the code is successfully validated.

  - **Access token requests using refresh token from a new User-Agent** are also verified:

    - The User-Agent is hashed and stored at token issuance.
    - On refresh, if the current User-Agent differs, a **confirmation step is triggered**.
    - This helps detect token reuse on unknown devices or browsers.

### Flexible Caching Support

- Blocklisted tokens are stored in **Redis (preferred)** or **in-memory fallback**.
- Ensures invalidated tokens are efficiently rejected during their remaining lifetime.
- Makes the logout experience **immediate and secure**, even with stateless JWTs.

## Features from previous levels

### Authentication

- Users register via `/auth/sign-up` by providing credentials: email, password, name, and surname.

### Authorization

- **Sign-In Route**: Users authenticate via `/auth/sign-in` using email and password.
- **Secure Routes**: Protected endpoints require access and refresh tokens stored in secure cookies.
- **Token Validation Middleware**:

  - Every request checks the `access_token` cookie.
  - If expired, the system uses the `refresh_token` (also from cookies) to issue a new access token.
  - The refresh token is validated against the database.
  - If the refresh token is invalid or expired:

    - It is removed from the DB.
    - Both cookies (`access_token` and `refresh_token`) are cleared.

  - Ensures short-lived access tokens and automatic session invalidation.

### Logout Route

- `/auth/sign-out` clears cookies and removes the refresh token from the database to fully log the user out.

### Expired Refresh Token Cleanup

- **CRON Job**:

  - Runs daily at **04:00 AM**.
  - Removes expired refresh tokens from the database to maintain security and performance.

### Database Management

- **Prisma ORM**: Type-safe PostgreSQL operations via Prisma.
- **Defined Schema**: Structured schema for clean and efficient data organization.

### Data Validation and Integrity

- **DTO-Based Validation**: Request/response schemas based on DTOs ensure consistent and secure data handling.
- **Validation Middleware**: Captures and processes invalid or malformed data.

### Security Measures

- **Built-in Middleware**:

  - CORS, Helmet, and rate limiting for robust protection.

- **XSS Protection**:

  - Helmet middleware sanitizes user input.

- **Rate Limiting**:

  - Prevents brute-force attempts.

- **Token Storage**:

  - Access & refresh tokens stored in `HTTP-only`, `secure`, `signed`, `sameSite: 'lax'` cookies.

### Testing Framework

- **End-to-End Testing**:

  - Uses Supertest for API testing and integration assurance.

- **Comprehensive Test Coverage**:

  - Ensures high reliability of critical features.

### Documentation and Discovery

- **Swagger UI**:

  - Available at `/api`, providing an interactive interface for exploring the API.

### Deployment and Containerization

- **Docker Support**:

  - Containerized environment for streamlined deployment and scalability.

### Email Confirmation During Registration

- **Email Verification Required**:

  - Users must confirm their email before gaining access.

- **Secure Code Handling**:

  - A random **6-digit code** is generated and **hashed** before storing in the database.

- **Code Resend Feature**:

  - Users can request a new confirmation email.

- **CRON Cleanup Job**:

  - Unconfirmed accounts (and related `profiles`, `confirmations`) are deleted after **2 days**.

- **Safe Entity Relationships**:

  - Deleting a user also removes related `profile` and `confirmation` records.

## Tech Stack

- **Backend Framework:** [NestJS](https://nestjs.com)
- **Programming Language:** [TypeScript](https://www.typescriptlang.org/)
- **Database:** [PostgreSQL](https://www.postgresql.org/)
- **ORM:** [Prisma](https://www.prisma.io/orm)
- **Authentication:** [JWT](https://jwt.io/), [cookie-parser](https://www.npmjs.com/package/cookie-parser)
- **API Documentation:** [Swagger](https://swagger.io/)
- **Rate Limiting:** [NestJS Throttler](https://docs.nestjs.com/security/rate-limiting)
- **Task Scheduling:** [NestJS Schedule](https://docs.nestjs.com/techniques/task-scheduling#task-scheduling)
- **Password & Token Hashing:** [Bcrypt](https://www.npmjs.com/package/bcrypt)
- **Security Enhancements:** [Helmet](https://www.npmjs.com/package/helmet)
- **Testing:** [Supertest](https://www.npmjs.com/package/supertest), [cookie-signature](https://www.npmjs.com/package/cookie-signature)
- **Email Service:** [Mailjet](https://www.mailjet.com/)
- **Cache Manager:** [Redis](https://redis.io/)

## Database Structure

- `users` table:
  - Stores `email`, `password` (hashed), `email_confirmed` (boolean), `two_factor_auth_enabled` (boolean), `two_factor_country` (hashed).
- `profiles` table:
  - Stores `name`, `surname`, and a references to the associated user.
- `confirmations` table:
  - Stores the **hashed** verification code and the type of the confirmation linked to a user. Attributes: `token` (hashed), `type`, and a reference to the associated user.
- `tokens` table:
  - Stores refresh `tokens` and the expiration time linked to a user. Attributes: `expires_at`, `two_factor_agent` (hashed), and a reference to the associated user.

## How It Works: General

### 1. User Sign-Up or Sign-In

The user's journey begins when they attempt to register or log in:

- **POST** `/auth/sign-up`: New users provide their email, password, name, and surname to create an account.
- **POST** `/auth/sign-in`: Existing users (with a confirmed email) provide their email and password to authenticate.

### 2. Server Validation

The server validates incoming data:

- For **sign-up**: ensures uniqueness of email and validates data structure.
- For **sign-in**: verifies that the user exists, the password is correct, and the email is confirmed.

### 3. Record Creation (Sign-Up Only)

Upon successful validation during registration, the server creates:

- A **user** record (`email`, `hashedPassword`, `emailConfirmed: false`).
- A **profile** record linked one-to-one with the user (`name`, `surname`).
- A **confirmation** record (`type: EMAIL_VERIFICATION`, `hashedCode`, `expiresAt`, and relation to the user).

Then, a **6-digit confirmation code** is sent to the user's email.

### 4. Email confirmation

The user gets the verification code from the letter and sends it to the **POST** `confirmation/verify` route; the server finds the confirmation record with the confirmation ID, compares the codes via bcrypt, and if everything is correct, deletes the confirmation record and marks the user's `emailConfirmed` field true. After this, the user could successfully sign in to the application.

### 5. Access Token Generation

Upon successful verification, the server generates a **short-lived access token (JWT)** for the user. This token contains essential information about the user, such as their ID.

### 6. Refresh Token Generation

The server generates the long-lived refresh token (UUID), which is stored in the database.

### 7. Client-Side Token Storage

The client-side application receives access and refresh tokens inside secured HTTP-only cookies from the server. These tokens will be automatically sent to the server with each request.

### 8. Accessing Protected Routes

Each time the client accesses a protected route, it automatically sends the access and refresh tokens from cookies with the request.

### 9. Backend Verification and Authorization

The backend server receives the request and verifies the validity of the access token. If the access token is valid, the request will successfully pass the security middleware and get to the controller. If the access token has expired or is undefined, the refresh token will generate a new access token. During this process, the refresh token is rigorously validated against the database. If valid, it’s reissued, but if expired or invalid, it’s immediately revoked (deleted from the database) and both the `access_token` and `refresh_token` cookies are cleared from the client.

### 10. User Sign-Out

**POST** `/auth/sign-out` clears the cookies, removes the refresh token from the database, and adds the access token to the blocklist for the remaining duration of its lifetime to ensure full logout.

### 11. Scheduled Cleanups (CRON Jobs)

The server will automatically start the CRON job to schedule a task that periodically deletes all:

- Expired refresh tokens from the database (every day, at 4:00 am).
- Users with unconfirmed email addresses, which have been created 2 days earlier from the database (every day, at 3:00 am). The delete setting in the database models is set up as `Cascade`, so when the user is deleted, all references to that user will be deleted too.

## How It Works: Two-Factor Authentication (2FA)

1. **User Enables 2FA**
   The user activates **Two-Factor Authentication (2FA)** by sending a **PATCH** request to the `security/two-factor-auth` endpoint. In response, the server updates the user’s record by setting the `twoFactorEnabled` flag to `true`, and storing the **hashed country** in the `twoFactorCountry` field. Additionally, when a refresh token is generated, the user's **hashed User-Agent** is stored in the `twoFactorAgent` field of the refresh token record.

2. **User Attempts to Sign In**
   The user sends credentials via **POST** `/auth/sign-in`. The server validates the credentials and checks if the user has confirmed their email.

3. **Country Verification**
   If **Two-Factor Authentication (2FA)** is enabled, the server compares the hashed country from the login request with the stored hashed country in the user's profile. If the country matches, the sign-in continues as usual. If it does not match, a 6-digit confirmation code is generated, hashed, stored as a confirmation record, and sent to the user’s email.

4. **2FA Country Code Verification**
   The user submits the confirmation code to the **POST** `/confirmation/verify` route. If valid, the server deletes the confirmation record and updates the `twoFactorCountry` field in the user’s profile with the new hashed country, completing the sign-in process.

5. **Access and Refresh Token Handling**
   After successful login, the server issues a short-lived JWT access token and a long-lived refresh token (UUID), which is stored in the database with the associated hashed user agent.

6. **Token Refresh Request**
   When the client later requests a new access token using the refresh token, the server compares the current user agent from the request with the hashed `twoFactorAgent` stored in the corresponding refresh token record.

7. **User-Agent Verification**
   If the hashed user agent does not match, the access token is blacklisted for the remainder of its lifespan, the refresh token is deleted from the database, both cookies are cleared, and the user must sign in again.

**Note!** If either the IP address or User-Agent is `null`, the system gracefully handles these scenarios without breaking the flow, ensuring a consistent and secure experience.

## Endpoints

| Method | Endpoint                    | Description                                   | Required Body                                  | Response                                |
| ------ | --------------------------- | --------------------------------------------- | ---------------------------------------------- | --------------------------------------- |
| POST   | `/auth/sign-up`             | Register a new user & send email confirmation | `email`, `password`, `name`, `surname`: string | `message`, `confirmationId`: string     |
| POST   | `/auth/sign-in`             | Login and set access & refresh token          | `email`: string, `password`: string            | `message`: string, set `auth cookies`   |
| POST   | `/auth/sign-out`            | Clear auth tokens and invalidate session      | None                                           | `message`: string, clear `auth cookies` |
| POST   | `/confirmation/verify`      | Verify confirmation                           | `confirmationId`: string, `token`: string      | `message`: string, set `auth cookies`   |
| POST   | `/confirmation/resend`      | Resend confirmation letter                    | `confirmationId`: string                       | `message`, `confirmationId`: string     |
| PATCH  | `/security/two-factor-auth` | Toggle user's two-factor authentication       | None                                           | `message`: string                       |

For a detailed overview of the available API endpoints, request/response structures, and data models, the Swagger documentation is available at `/api`. This documentation provides interactive API exploration and helps developers understand and integrate with the API efficiently.

## Example Request

```http
POST /auth/sign-in
{
  "email": "example@gmail.com",
  "password": "examplePassword123"
}
```

### Response

#### Body

```json
{
  "message": "User successfully logged in"
}
```

#### Headers

```headers
Set-Cookie: access_token=s%...; Path=/; HttpOnly; Secure; Expires=...GMT
Set-Cookie: refresh_token=s%...; Path=/; HttpOnly; Secure; Expires=...GMT
```

## Configurations

### Cookie

- **httpOnly**: `true`
- **secure**: `true`
- **sameSite**: `lax`
- **signed**: `true`
- **maxAge**: `15 minutes for access token and 7 days for refresh token (should be set in milliseconds)`
- **path**: `/`

### Confirmation

- **Verification time**: `15 minutes to verify the email address. Provided in milliseconds`
- **Resend threshold**: `Verification time/3 - 5 minutes. Provided in milliseconds. After this time, the user can request a new email confirmation letter`

### Letters

- **senderName**: `Support Team`
- **senderEmail**: `The email address from which emails will be sent. Must be verified on Mailjet website. Stores in environment variables(.env)`
- **Email Verification**: Template id: `6922624`, subject: `Confirm Your Email Address`
- **Two-Factor Auth**: Template id: `6957048`, subject: `Confirm Your Sign-In`
- **General confirmation letter**: Template id: `6957060`, subject: `Your verification code`

## Security Improvements Over Level 2

Compared to Level 2, which focused primarily on identity confirmation through email verification, this level introduces a more robust and context-aware security model. While email verification ensures that the account belongs to a real user with access to a valid inbox, it does not protect against token theft, reuse, or suspicious login patterns. This level addresses those concerns through the following enhancements:

- **Token Invalidation After Logout**: By implementing token blocklisting, access tokens can no longer be reused after logout, reducing the risk of session hijacking.

- **Contextual Binding via User-Agent and IP**: Tokens are bound to the user's environment using hashed User-Agent and IP address, helping to detect and block suspicious reuse from unfamiliar devices or networks.

- **Two-Factor Authentication (2FA)**: Users can optionally enable 2FA, adding an additional layer of protection based on their country and device fingerprint. The system stores the hashed country in the user’s profile and the hashed User-Agent in the refresh token metadata.

- **Geographic Anomaly Detection**: If a login attempt is made from a different country than the one associated with the user’s 2FA configuration, additional verification (e.g., a 2FA code) may be triggered.

- **Flexible Token Storage Layer**: A caching system (e.g., Redis) ensures efficient lookup of invalidated tokens without sacrificing statelessness.

Together, these improvements elevate security from simple identity validation to proactive defense against common threats in token-based authentication systems, such as token replay, session fixation, and unauthorized access from compromised devices.

## Security Notes

### ✅ Recommended for Production Use – With Conditions

This level introduces a **significant security enhancement** over previous authentication strategies and is generally **suitable for production environments, assuming correct implementation and adherence to best practices**.

Building on the foundation of email verification, Level 3 adds **token invalidation**, **User-Agent and IP-based heuristics**, and **optional Two-Factor Authentication (2FA)** with country and device binding. These features greatly strengthen resistance to token theft, replay attacks, and unauthorized access, especially in logout and refresh scenarios.

However, as with all security-critical features, `production-readiness relies heavily on secure deployment, thorough testing, and continuous monitoring`.

### Use Cases Where This Level Is a Good Fit

- Applications requiring stronger protections against token replay and session hijacking
- Public platforms where users can access sensitive account data
- SaaS products that aim to add 2FA without moving to full enterprise SSO
- Systems where contextual login validation (e.g. country, device) is important

### Use with Caution If:

- Your application stores or processes **highly regulated or critical data** (e.g., healthcare, financial records)
- You face **state-level or highly targeted attacks**
- You require **hardware-based MFA**, biometric factors, or **enterprise-grade access control**

---

> 🧠 TL;DR:  
> Yes — this level **can be confidently used in production**, provided that HTTPS, cookie security settings, email service hardening, secure hashing algorithms, proper token storage (e.g., Redis) and periodic system audits are properly maintained. For high-risk systems, consider layering with additional protections such as biometric MFA, behavioral analysis, and adaptive access policies.

---

## Testing

To ensure the application is working correctly, comprehensive testing has been implemented to cover all aspects of the JWT authentication flow. The application utilizes Supertest for E2E testing, which allows making HTTP requests directly from test code and verifying expected responses. Here's a snapshot of the test results:

<img src="https://i.ibb.co/WpHvtWHb/image-2025-05-16-02-02-03.png" width="280" alt="Test results" />

As you can see, all tests passed successfully. This gives confidence in the correctness of the JWT authentication implementation and ensures it works as expected in different scenarios. You can also run this test cases using `npm run test:e2e` command.

## Installation

### GitHub

```bash
$ git clone https://github.com/Pier228/level-3-advanced-token-protection.git
$ cd level-3-advanced-token-protection
$ npm install
```

### Docker Image

The Docker image for this project is available on [Docker Hub](https://hub.docker.com/r/pier276/level-3-advanced-token-protection).

[![Docker Hub](https://img.shields.io/badge/Docker-Hub-blue)](https://hub.docker.com/r/pier276/level-3-advanced-token-protection)

## Environment Variables

To run this application, you need to configure several environment variables.

1. Create a .env file in the root directory of the project.
2. Add required environment variables:

- `PORT`: The port on which the server will run. This field is **optional**. By default will run on 3000 port.
- `DATABASE_URL`: MongoDB connection URL used to connect to the database.
- `SALT_ROUNDS`: Number of rounds for hashing passwords (bcrypt).
- `JWT_SECRET`: Secret key for signing and verifying JWT tokens.
- `CORS_ALLOWED_ORIGIN`: The URL of the domain from which it is allowed to send requests to the server (CORS settings).
- `COOKIE_SECRET`: Secret key for signing and verifying cookies.
- `MAILJET_API_KEY`: Public API key from Mailjet.
- `MAILJET_SECRET_KEY`: Private API secret key from Mailjet.
- `MAILJET_SENDER_EMAIL`: Default sender email address (must be verified in Mailjet).
- `REDIS_CONNECT`: Redis connection URL.

You can also refer to the [.env.example](./.env.example) file for a complete list of required environment variables.

## Running the app

After setting up the .env file, you can start the application using the following commands:

```bash
# Generate prisma client
$ npx prisma generate

# Build the application
$ npm run build

# Start in development mode
$ npm run start

# Start in watch mode
$ npm run start:dev

# Start in production mode
$ npm run start:prod
```

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
