# 🛡️ SecurePass — Enterprise-Grade Password Resilience & Analysis Platform

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen?style=flat-square)](https://github.com/heytarunkumar/securepass)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-blue?style=flat-square&logo=typescript)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-18.3-61dafb?style=flat-square&logo=react)](https://react.dev/)
[![Express](https://img.shields.io/badge/Express-4.18-lightgrey?style=flat-square&logo=express)](https://expressjs.com/)
[![Security Audited](https://img.shields.io/badge/Security_Audit-SP--01_to_SP--15_Remediated-success?style=flat-square&logo=shield)](https://github.com/heytarunkumar/securepass)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](./LICENSE)

**SecurePass** is a production-hardened password intelligence and resilience analysis suite. It provides real-time entropy quantification, advanced brute-force crack-time estimation, k-anonymity data breach verification via Have I Been Pwned (HIBP), user vault management, and an audited administrative control center.

---

## ✨ Features

### 🔍 1. Real-Time Password Intelligence & Resilience Analyzer
- **Entropy Quantification**: Measures password complexity in bits based on character space and length.
- **Advanced Attack Modeling**: Simulates offline GPU brute-force scenarios ($10^9$ guesses/sec cluster) with explicit assumption disclosure.
- **Heuristic Pattern Detection**:
  - Dictionary word matching against common credential corpuses.
  - Keyboard walk detection (`qwerty`, `asdfgh`, `12345`).
  - Leetspeak substitution normalization (`p@ssw0rd` $\rightarrow$ `password`).
  - Sequential character and repetition penalties.
- **Privacy-Preserving K-Anonymity Breach Checking**:
  - Calculates SHA-1 transiently in local process scope.
  - Sends only the 5-character prefix to HIBP API (range queries).
  - Tri-state reporting: `breached`, `clean`, or `unavailable` (never produces false-safe results upon network timeout).
  - Bounded LRU/TTL cache of anonymous range prefixes — **zero passwords or password hashes are ever cached or stored**.

### 🔐 2. Enterprise Authentication & Session Management
- **Bcrypt (12 Rounds)**: Asynchronous password hashing on request paths.
- **Server-Side Session Revocation**: Every token is indexed in a server-side `sessions` table; logging out or administrative deactivation revokes access instantly.
- **Real-Time Account Validation**: Requests re-verify active database status on every authenticated call.
- **Multi-Tier Throttling**:
  - Per-IP rate limiting to prevent automated credential stuffing.
  - Per-(IP + Email) progressive throttling preventing malicious denial-of-service on victim accounts.
  - Standardized generic authentication failure messages.
- **Strict Input Validation**: Zod runtime schemas enforcing email normalization, RFC 5322 compliance, and 72-character maximum password bounds (preventing bcrypt truncation attacks).

### 📊 3. Audited Administrative Dashboard
- **System Telemetry**: Real-time counts of registered accounts, analysis cycles, breached credentials found, and resilience distribution.
- **Entity Access Controls**: Safely authorize or revoke user access.
- **Last-Admin Deletion Safeguard**: System programmatically rejects deactivating or deleting the last active administrator account.
- **Append-Only Security Audit Trail**: Records administrator identity, action, target entity, timestamp, metadata, and client IP without leaking sensitive secrets.

---

## 🔒 Security Architecture & Audit Hardening

SecurePass was audited against static and runtime vulnerability baselines (**SP-01 through SP-15**):

- **SP-01 (No Default Admin)**: Hardcoded administrative accounts and credentials removed. Replaced with an explicit, one-time bootstrap utility (`npm run bootstrap:admin`).
- **SP-02 (Zero Password Retention)**: Database tables (`password_checks`, `password_history`) store only non-sensitive aggregate strength metadata. No raw passwords or unsalted SHA-256 digests exist in memory or disk.
- **SP-03 (Enforced Cryptographic Secrets)**: Application startup halts in production if `JWT_SECRET` is missing or below 32 characters. Access tokens are short-lived (1 hour default).
- **SP-04 (Tri-State Breach Verification)**: Native `node:crypto` with 3.5s timeout; API distinguishes between confirmed clean and upstream service unavailability.
- **SP-05 (Server-Side Session Revocation)**: Tokens are validated in real-time against SQLite `sessions` table and user active state.
- **SP-07 (Abuse-Resistant Throttling)**: Dual-layer rate limiting and `trust proxy` configuration preventing victim lockout.
- **SP-08 & SP-09 (Defense-in-Depth Middleware)**:
  - 16 KB request body caps.
  - Origin-allowlisted CORS.
  - Security headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security`, and strict `Content-Security-Policy`.
- **SP-13 (Audit Logging)**: All administrator operations create persistent audit log records.

---

## 🛠️ Tech Stack

- **Frontend**: React 18, React Router 6 (SPA mode), TypeScript, Vite, TailwindCSS 3, Radix UI, Lucide Icons, Framer Motion.
- **Backend**: Node.js, Express, TypeScript, Better-SQLite3, Zod, JsonWebToken, Bcrypt.js.
- **Testing**: Vitest, native HTTP test runners.

---

## 🚀 Getting Started

### Prerequisites
- **Node.js**: v18.0.0 or higher (v20+ recommended)
- **npm**: v9+

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/heytarunkumar/securepass.git
cd securepass
npm install
```

### 2. Configure Environment Variables
Create a `.env` file in the root directory:
```env
PORT=8080
NODE_ENV=development
JWT_SECRET=your-32-character-or-longer-secure-random-jwt-secret-string
JWT_EXPIRES_IN=1h
```

### 3. Bootstrap the Initial Administrator (SP-01)
To create the first administrative account, run the secure one-time bootstrap CLI:
```bash
# Option 1: Via Environment Variables
ADMIN_BOOTSTRAP_EMAIL="admin@yourdomain.com" ADMIN_BOOTSTRAP_PASSWORD="YourStrongPassword123!@#" npm run bootstrap:admin

# Option 2: Via CLI Arguments
npm run bootstrap:admin -- admin@yourdomain.com "YourStrongPassword123!@#"
```
> *Note: Administrator passwords must be at least 12 characters long and include uppercase, lowercase, numbers, and special characters.*

### 4. Start Development Server
```bash
npm run dev
```
The application will be running at [http://localhost:8080](http://localhost:8080).

---

## 🧪 Testing & Validation

Run the automated test suite covering unit functionality and security audit verifications:
```bash
# Run Vitest test suite
npm test

# Run TypeScript compilation check
npm run typecheck

# Build client and server bundles for production
npm run build
```

---

## 🌐 Production Deployment

See [DEPLOYMENT.md](./DEPLOYMENT.md) for full deployment instructions across different environments.

### Recommended: Persistent Hosts (Railway, Render, VPS)
Because SQLite requires a persistent disk volume to retain accounts and sessions across restarts:
1. Deploy to a persistent container provider (Railway, Render, Fly.io, or VPS).
2. Attach a persistent volume (e.g. `/app/data`).
3. Set `DATABASE_PATH=/app/data/securepass.db`.
4. Configure production environment variables:
   ```env
   NODE_ENV=production
   JWT_SECRET=<cryptographically-random-32+-char-secret>
   CORS_ORIGIN=https://your-domain.com
   ```

### Serverless Deployments (Vercel)
> ⚠️ **Architecture Notice**: On serverless platforms like Vercel, the local filesystem (`/tmp`) is ephemeral. For production serverless deployments, connect an external managed relational database (such as Neon PostgreSQL or Supabase).

---

## 📄 License

This project is licensed under the [MIT License](./LICENSE).
