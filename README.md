# Marketplace Auth Service

Production-grade authentication and authorization microservice for the Marketplace platform.

---

## Overview

The Auth Service is the central identity and access management system for Marketplace.

It provides:

- User registration
- User login/logout
- JWT authentication
- Refresh token management
- Redis-backed session storage
- Role-Based Access Control (RBAC)
- Two-Factor Authentication (2FA)
- OAuth provider integration (Google & Apple)
- Account lockout protection
- Rate limiting
- Security hardening

This service acts as the single source of truth for user identity across all Marketplace applications.

---

# Architecture

```text
Customer App
Professional App
Admin Dashboard
        │
        ▼
   Auth Service
        │
 ┌──────┴──────┐
 ▼             ▼
PostgreSQL   Redis
(User Data)  (Sessions & Tokens)
```

---

# Technology Stack

## Backend

- Node.js
- Express.js

## Database

- PostgreSQL

## Cache & Sessions

- Redis

## Authentication

- JWT
- bcrypt

## Security

- Helmet
- Rate Limiting
- RBAC
- 2FA (Speakeasy)

## Validation

- Zod

---

# Features

## Authentication

### Register

```http
POST /auth/register
```

Creates a new user account.

### Login

```http
POST /auth/login
```

Authenticates a user and issues tokens.

### Logout

```http
POST /auth/logout
```

Revokes active refresh token and terminates session.

### Refresh Token

```http
POST /auth/refresh
```

Generates a new access token and rotates refresh tokens securely.

---

# Authorization

Marketplace uses Role-Based Access Control (RBAC).

Available roles:

### Customer

Permissions:

- Browse services
- Book professionals
- Payments
- Ratings
- Messaging

### Professional

Permissions:

- Manage services
- Accept/reject bookings
- Availability management
- Earnings tracking

### Admin

Permissions:

- Internal dashboard access
- User management
- Platform moderation
- Security monitoring

---

# User Roles

```text
customer
professional
admin
```

Admin accounts are internal-only and cannot be created through public registration.

---

# JWT Authentication

## Access Token

Purpose:

- API authentication

Expiration:

```text
15 minutes
```

## Refresh Token

Purpose:

- Obtain new access tokens

Expiration:

```text
7 days
```

Refresh tokens are stored securely in Redis.

---

# Session Management

Sessions are managed using Redis.

## Redis Key Structure

### Refresh Tokens

```text
refresh:{userId}:{sessionId}
```

### Failed Login Counter

```text
auth:fail:{email}
```

### Account Lock

```text
auth:lock:{email}
```

### User Sessions

```text
user:sessions:{userId}
```

---

# Refresh Token Rotation

Every refresh operation:

1. Validates existing refresh token
2. Invalidates old token
3. Creates new refresh token
4. Issues new access token
5. Stores new token in Redis

Benefits:

- Prevents token replay attacks
- Improves session security
- Supports multi-device session management

---

# Account Protection

## Login Lockout

Protection against brute-force attacks.

Rules:

```text
5 failed login attempts
↓
Account locked for 15 minutes
```

Tracked through Redis.

---

# Two-Factor Authentication (2FA)

Supported using TOTP.

Features:

- Generate secret
- Enable 2FA
- Disable 2FA
- Verify code during login

Powered by:

```text
speakeasy
```

---

# OAuth Support

Supported providers:

- Google
- Apple

OAuth flow:

```text
User
 ↓
OAuth Provider
 ↓
Callback
 ↓
Auto Provision User
 ↓
JWT Issued
```

---

# API Structure

```text
/auth/register
/auth/login
/auth/logout
/auth/refresh

/auth/2fa/setup
/auth/2fa/enable
/auth/2fa/disable
/auth/2fa/verify
```

---

# Project Structure

```text
auth-service/
├── src/
│   ├── config/
│   │   ├── db.js
│   │   └── redis.js
│   │
│   ├── controllers/
│   ├── services/
│   ├── routes/
│   ├── middleware/
│   ├── models/
│   ├── validators/
│   ├── utils/
│   └── server.js
│
├── .env
├── package.json
└── README.md
```

---

# Environment Variables

```env
PORT=3000

DATABASE_URL=

REDIS_URL=

JWT_ACCESS_SECRET=
JWT_REFRESH_SECRET=

ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=7d

GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

APPLE_CLIENT_ID=
APPLE_CLIENT_SECRET=
```

---

# Security Features

- Password hashing with bcrypt
- JWT authentication
- Refresh token rotation
- Redis-backed sessions
- Role-Based Access Control
- Account lockout protection
- Rate limiting
- Helmet security headers
- Input validation with Zod
- OAuth support
- Two-Factor Authentication

---

# Production Goals

This service is designed to be:

- Secure
- Scalable
- Stateless
- Cloud-ready
- Microservice-compatible
- Enterprise-grade

---

# Marketplace Ecosystem

This service is consumed by:

- Customer Application
- Professional Application
- Admin Dashboard
- Future Internal Services

The Auth Service remains the single source of truth for authentication and authorization across the Marketplace platform.

