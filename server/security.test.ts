import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import type { Server } from 'http';
import { createServer } from './index';
import db, { userDb, sessionDb, adminAuditDb } from './database';
import { generateToken, hashPassword, hashToken } from './auth';
import { RegistrationSchema, LoginSchema, PasswordAnalysisSchema } from './validation';
import { v4 as uuidv4 } from 'uuid';

describe('Security Audit Acceptance Tests (SP-01 to SP-14)', () => {
  let server: Server;
  let baseUrl: string;

  beforeAll(async () => {
    const app = createServer();
    await new Promise<void>((resolve) => {
      server = app.listen(0, '127.0.0.1', () => {
        const address = server.address() as any;
        baseUrl = `http://127.0.0.1:${address.port}`;
        resolve();
      });
    });
  });

  afterAll(() => {
    server?.close();
  });

  beforeEach(() => {
    sessionDb.cleanupExpired();
  });

  describe('SP-01: Hardcoded default administrator elimination', () => {
    it('does not have a default admin with legacy password SecurePass2024!', () => {
      const admin = userDb.findAnyByEmail('admin@securepass.com');
      if (admin) {
        const bcrypt = require('bcryptjs');
        const isLegacyMatch = bcrypt.compareSync('SecurePass2024!', admin.password_hash);
        expect(isLegacyMatch).toBe(false);
      }
    });

    it('fresh startup does not print or recreate hardcoded default credentials', () => {
      const adminUser = db.prepare("SELECT * FROM users WHERE email = 'admin@securepass.com'").get() as any;
      if (adminUser) {
        expect(adminUser.password_hash).not.toContain('SecurePass2024!');
      }
    });
  });

  describe('SP-02: Zero password retention or unsalted fingerprints', () => {
    it('ensures password_history and password_checks do not store plain passwords or SHA-256 digests', async () => {
      const testEmail = `test-user-${Date.now()}@example.com`;
      const testPassword = 'SafePassword2026!@#$';
      const hash = await hashPassword(testPassword);
      const user = userDb.create(testEmail, hash, 'user');

      const sessionId = uuidv4();
      const token = generateToken({ id: user.id, email: user.email, role: 'user' }, sessionId);
      sessionDb.create(sessionId, user.id, hashToken(token), new Date(Date.now() + 3600000));

      const res = await fetch(`${baseUrl}/api/password-analysis`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ password: testPassword, saveToHistory: true }),
      });

      expect(res.status).toBe(200);

      // Verify DB rows for this check
      const historyRow = db.prepare('SELECT * FROM password_history WHERE user_id = ?').get(user.id) as any;
      expect(historyRow).toBeDefined();
      expect(historyRow.password_hash).toBeNull(); // SP-02: Never stored

      const checksRow = db.prepare('SELECT * FROM password_checks WHERE user_id = ?').get(user.id) as any;
      expect(checksRow).toBeDefined();
      expect(checksRow.password_hash).toBeNull(); // SP-02: Never stored
    });
  });

  describe('SP-03: JWT secret strength enforcement', () => {
    it('throws in production if JWT_SECRET is absent or weak (< 32 chars)', async () => {
      const prevEnv = process.env.NODE_ENV;
      const prevSecret = process.env.JWT_SECRET;

      process.env.NODE_ENV = 'production';
      delete process.env.JWT_SECRET;

      const { verifyToken } = await import('./auth');
      expect(() => verifyToken('some.fake.token')).toThrow(/FATAL SECURITY ERROR \(SP-03\)/);

      process.env.NODE_ENV = prevEnv;
      process.env.JWT_SECRET = prevSecret;
    });
  });

  describe('SP-04: Breach check tri-state and error handling', () => {
    it('returns valid analysis schema with breachStatus field', async () => {
      const res = await fetch(`${baseUrl}/api/password-analysis`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: 'Password123!@#' }),
      });

      expect(res.status).toBe(200);
      const data: any = await res.json();
      expect(data).toHaveProperty('score');
      expect(data).toHaveProperty('strength');
      expect(data).toHaveProperty('crackTime');
      expect(data).toHaveProperty('breachStatus');
      expect(['breached', 'clean', 'unavailable']).toContain(data.breachStatus);
    });
  });

  describe('SP-05: Real-time user deactivation and session revocation', () => {
    it('rejects access immediately if user is deactivated', async () => {
      const email = `deact-${Date.now()}@example.com`;
      const hash = await hashPassword('ValidPass123!@#');
      const user = userDb.create(email, hash, 'user');

      const sessionId = uuidv4();
      const token = generateToken({ id: user.id, email: user.email, role: 'user' }, sessionId);
      sessionDb.create(sessionId, user.id, hashToken(token), new Date(Date.now() + 3600000));

      // Active user can access profile
      const res1 = await fetch(`${baseUrl}/api/auth/profile`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      expect(res1.status).toBe(200);

      // Deactivate user in database
      userDb.updateStatus(user.id, false);

      // Same token must now be rejected
      const res2 = await fetch(`${baseUrl}/api/auth/profile`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      expect(res2.status).toBe(403);
    });

    it('revokes session on logout so token cannot be reused', async () => {
      const email = `logout-${Date.now()}@example.com`;
      const hash = await hashPassword('ValidPass123!@#');
      const user = userDb.create(email, hash, 'user');

      const sessionId = uuidv4();
      const token = generateToken({ id: user.id, email: user.email, role: 'user' }, sessionId);
      sessionDb.create(sessionId, user.id, hashToken(token), new Date(Date.now() + 3600000));

      // Log out
      const logoutRes = await fetch(`${baseUrl}/api/auth/logout`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
      });
      expect(logoutRes.status).toBe(200);

      // Subsequent request using revoked token fails
      const profileRes = await fetch(`${baseUrl}/api/auth/profile`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      expect(profileRes.status).toBe(401);
    });
  });

  describe('SP-08: Bounded input and memory limits', () => {
    it('rejects passwords longer than 256 characters on analysis endpoint', async () => {
      const oversizedPassword = 'A'.repeat(300);
      const res = await fetch(`${baseUrl}/api/password-analysis`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: oversizedPassword }),
      });

      expect(res.status).toBe(400);
      const data: any = await res.json();
      expect(data.error).toMatch(/exceeds maximum/);
    });
  });

  describe('SP-09: Security headers and CORS configuration', () => {
    it('includes required defense-in-depth security headers', async () => {
      const res = await fetch(`${baseUrl}/api/ping`);

      expect(res.headers.get('x-content-type-options')).toBe('nosniff');
      expect(res.headers.get('x-frame-options')).toBe('DENY');
      expect(res.headers.get('referrer-policy')).toBe('strict-origin-when-cross-origin');
      expect(res.headers.get('content-security-policy')).toBeDefined();
    });

    it('allows requests from Vercel deployment origins without crashing', async () => {
      const res = await fetch(`${baseUrl}/api/ping`, {
        headers: { 'Origin': 'https://securepass.vercel.app' },
      });

      expect(res.status).toBe(200);
      expect(res.headers.get('access-control-allow-origin')).toBe('https://securepass.vercel.app');
    });

    it('processes password analysis from Vercel deployment origins successfully', async () => {
      const res = await fetch(`${baseUrl}/api/password-analysis`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Origin': 'https://my-preview.vercel.app',
        },
        body: JSON.stringify({ password: 'TestSecurePass2026!' }),
      });

      expect(res.status).toBe(200);
      expect(res.headers.get('access-control-allow-origin')).toBe('https://my-preview.vercel.app');
      const data: any = await res.json();
      expect(data.score).toBeGreaterThan(0);
      expect(data.strength).toBeDefined();
    });
  });


  describe('SP-11: Input validation schemas', () => {
    it('validates registration input with Zod', () => {
      const invalid = RegistrationSchema.safeParse({
        email: 'invalid-email',
        password: 'short',
        confirmPassword: 'short',
      });
      expect(invalid.success).toBe(false);

      const oversized = RegistrationSchema.safeParse({
        email: 'valid@example.com',
        password: 'A'.repeat(80) + '1!a',
        confirmPassword: 'A'.repeat(80) + '1!a',
      });
      expect(oversized.success).toBe(false); // Max 72 chars
    });
  });

  describe('SP-13: Admin audit logging and last admin safeguard', () => {
    it('prevents deactivating or deleting the last active admin', async () => {
      const adminEmail = `admin-${Date.now()}@example.com`;
      const adminHash = await hashPassword('AdminPass123!@#$');
      const adminUser = userDb.create(adminEmail, adminHash, 'admin');

      const adminSessionId = uuidv4();
      const adminToken = generateToken({ id: adminUser.id, email: adminUser.email, role: 'admin' }, adminSessionId);
      sessionDb.create(adminSessionId, adminUser.id, hashToken(adminToken), new Date(Date.now() + 3600000));

      // Attempt to deactivate if only 1 active admin exists
      if (userDb.countActiveAdmins() === 1) {
        const deleteRes = await fetch(`${baseUrl}/api/admin/users/${adminUser.id}`, {
          method: 'DELETE',
          headers: { 'Authorization': `Bearer ${adminToken}` },
        });

        expect(deleteRes.status).toBe(400);
        const data: any = await deleteRes.json();
        expect(data.message).toMatch(/cannot delete/i);
      }
    });

    it('records an audit event when an admin updates user status', async () => {
      const adminEmail = `audit-admin-${Date.now()}@example.com`;
      const adminHash = await hashPassword('AdminPass123!@#$');
      const admin = userDb.create(adminEmail, adminHash, 'admin');

      const adminSessionId = uuidv4();
      const adminToken = generateToken({ id: admin.id, email: admin.email, role: 'admin' }, adminSessionId);
      sessionDb.create(adminSessionId, admin.id, hashToken(adminToken), new Date(Date.now() + 3600000));

      const targetEmail = `target-${Date.now()}@example.com`;
      const targetHash = await hashPassword('UserPass123!@#$');
      const target = userDb.create(targetEmail, targetHash, 'user');

      const res = await fetch(`${baseUrl}/api/admin/users/${target.id}/status`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${adminToken}`,
        },
        body: JSON.stringify({ isActive: false }),
      });

      expect(res.status).toBe(200);

      // Verify audit log entry exists
      const logs = adminAuditDb.getAll(10, 0);
      const matchingLog = logs.find((l) => l.targetId === target.id);
      expect(matchingLog).toBeDefined();
      expect(matchingLog.action).toBe('USER_DEACTIVATE');
      expect(matchingLog.adminEmail).toBe(admin.email);
    });
  });
});
