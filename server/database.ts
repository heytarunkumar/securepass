import Database from 'better-sqlite3';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';
import path from 'node:path';
import fs from 'node:fs';

// SP-06 & Serverless Architecture resilience
const isServerless =
  process.env.VERCEL === '1' ||
  !!process.env.VERCEL_ENV ||
  !!process.env.VERCEL_URL ||
  !!process.env.AWS_LAMBDA_FUNCTION_NAME ||
  !!process.env.LAMBDA_TASK_ROOT;

const preferredDbPath =
  process.env.DATABASE_PATH ||
  (isServerless ? (process.platform === 'win32' ? 'securepass.db' : path.join('/tmp', 'securepass.db')) : 'securepass.db');

let db: any = null;
let useMemoryFallback = false;

// In-Memory Data Structures for seamless fallback in serverless/read-only environments
interface MemoryUser {
  id: string;
  email: string;
  password_hash: string;
  role: 'user' | 'admin';
  two_factor_enabled: number;
  created_at: string;
  last_login: string | null;
  is_active: number;
}

interface MemorySession {
  id: string;
  user_id: string;
  token_hash: string;
  expires_at: string;
  is_revoked: number;
  created_at: string;
}

interface MemoryPasswordHistory {
  id: string;
  user_id: string;
  password_hash: null;
  strength_score: number;
  strength_level: string;
  entropy: number;
  is_breached: number;
  breach_count: number;
  created_at: string;
}

interface MemoryPasswordCheck {
  id: string;
  user_id: string | null;
  password_hash: null;
  strength_score: number;
  strength_level: string;
  entropy: number;
  is_breached: number;
  breach_count: number;
  ip_address: string | null;
  user_agent: string | null;
  created_at: string;
}

interface MemoryLoginAttempt {
  id: string;
  email: string;
  success: number;
  ip_address: string | null;
  user_agent: string | null;
  failure_reason: string | null;
  created_at: string;
}

interface MemoryAdminAuditLog {
  id: string;
  adminId: string;
  adminEmail: string;
  action: string;
  targetType: string;
  targetId: string | null;
  details: string | null;
  ipAddress: string | null;
  createdAt: string;
}

const memoryUsers = new Map<string, MemoryUser>();
const memorySessions = new Map<string, MemorySession>();
const memoryPasswordHistory: MemoryPasswordHistory[] = [];
const memoryPasswordChecks: MemoryPasswordCheck[] = [];
const memoryLoginAttempts: MemoryLoginAttempt[] = [];
const memoryAdminAuditLogs: MemoryAdminAuditLog[] = [];

try {
  const dir = path.dirname(path.resolve(preferredDbPath));
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  db = new Database(preferredDbPath);
  db.pragma('foreign_keys = ON');

  // Initialize SQLite schema
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'user' CHECK (role IN ('user', 'admin')),
      two_factor_enabled INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login DATETIME,
      is_active INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at DATETIME NOT NULL,
      is_revoked INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS password_history (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      password_hash TEXT,
      strength_score INTEGER NOT NULL,
      strength_level TEXT NOT NULL,
      entropy REAL NOT NULL,
      is_breached INTEGER DEFAULT 0,
      breach_count INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS password_checks (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      password_hash TEXT,
      strength_score INTEGER NOT NULL,
      strength_level TEXT NOT NULL,
      entropy REAL NOT NULL,
      is_breached INTEGER DEFAULT 0,
      breach_count INTEGER DEFAULT 0,
      ip_address TEXT,
      user_agent TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS login_attempts (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL,
      ip_address TEXT,
      user_agent TEXT,
      success INTEGER NOT NULL,
      failure_reason TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS breach_alerts (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      breach_count INTEGER NOT NULL,
      notified INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS admin_audit_logs (
      id TEXT PRIMARY KEY,
      admin_id TEXT NOT NULL,
      admin_email TEXT NOT NULL,
      action TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target_id TEXT,
      details TEXT,
      ip_address TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Migration helper for legacy schema
  try {
    const tableInfoHistory = db.pragma('table_info(password_history)') as Array<{ name: string; notnull: number }>;
    const hashColHistory = tableInfoHistory.find(col => col.name === 'password_hash');
    if (hashColHistory && hashColHistory.notnull === 1) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS password_history_new (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL,
          password_hash TEXT,
          strength_score INTEGER NOT NULL,
          strength_level TEXT NOT NULL,
          entropy REAL NOT NULL,
          is_breached INTEGER DEFAULT 0,
          breach_count INTEGER DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        INSERT INTO password_history_new SELECT id, user_id, NULL, strength_score, strength_level, entropy, is_breached, breach_count, created_at FROM password_history;
        DROP TABLE password_history;
        ALTER TABLE password_history_new RENAME TO password_history;
      `);
    }

    const tableInfoChecks = db.pragma('table_info(password_checks)') as Array<{ name: string; notnull: number }>;
    const hashColChecks = tableInfoChecks.find(col => col.name === 'password_hash');
    if (hashColChecks && hashColChecks.notnull === 1) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS password_checks_new (
          id TEXT PRIMARY KEY,
          user_id TEXT,
          password_hash TEXT,
          strength_score INTEGER NOT NULL,
          strength_level TEXT NOT NULL,
          entropy REAL NOT NULL,
          is_breached INTEGER DEFAULT 0,
          breach_count INTEGER DEFAULT 0,
          ip_address TEXT,
          user_agent TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        INSERT INTO password_checks_new SELECT id, user_id, NULL, strength_score, strength_level, entropy, is_breached, breach_count, ip_address, user_agent, created_at FROM password_checks;
        DROP TABLE password_checks;
        ALTER TABLE password_checks_new RENAME TO password_checks;
      `);
    }
  } catch (e) {
    // Migration fallback
  }

  // SP-02: Purge any legacy unsalted digests from existing records
  try {
    db.exec(`
      UPDATE password_history SET password_hash = NULL WHERE password_hash IS NOT NULL;
      UPDATE password_checks SET password_hash = NULL WHERE password_hash IS NOT NULL;
    `);
  } catch (e) {
    // Ignore
  }

  // SP-01: Remove vulnerable legacy hardcoded default admin account if present
  try {
    const legacyAdmin = db.prepare("SELECT id, password_hash FROM users WHERE email = 'admin@securepass.com'").get() as { id: string; password_hash: string } | undefined;
    if (legacyAdmin && bcrypt.compareSync('SecurePass2024!', legacyAdmin.password_hash)) {
      db.prepare('DELETE FROM users WHERE id = ?').run(legacyAdmin.id);
      console.warn('⚠️ [SECURITY REMEDIATION (SP-01)]: Purged vulnerable default admin account.');
    }
  } catch (e) {
    // Ignore
  }
} catch (err) {
  console.warn('⚠️ [DATABASE ADAPTER]: Native SQLite connection unavailable or disk read-only. Activating resilient in-memory storage adapter:', err);
  useMemoryFallback = true;
}

// User database operations
export const userDb = {
  create: (email: string, passwordHash: string, role: 'user' | 'admin' = 'user') => {
    const normalizedEmail = email.toLowerCase().trim();
    const id = uuidv4();
    const createdAt = new Date().toISOString();

    if (!useMemoryFallback && db) {
      const stmt = db.prepare(`
        INSERT INTO users (id, email, password_hash, role, created_at)
        VALUES (?, ?, ?, ?, ?)
      `);
      try {
        stmt.run(id, normalizedEmail, passwordHash, role, createdAt);
        return { id, email: normalizedEmail, role, created_at: createdAt };
      } catch (error: any) {
        if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
          throw new Error('Email already exists');
        }
        throw error;
      }
    }

    // In-memory fallback
    for (const u of memoryUsers.values()) {
      if (u.email === normalizedEmail) {
        throw new Error('Email already exists');
      }
    }

    const newUser: MemoryUser = {
      id,
      email: normalizedEmail,
      password_hash: passwordHash,
      role,
      two_factor_enabled: 0,
      created_at: createdAt,
      last_login: null,
      is_active: 1,
    };
    memoryUsers.set(id, newUser);
    return { id, email: normalizedEmail, role, created_at: createdAt };
  },

  findByEmail: (email: string) => {
    const normalized = email.toLowerCase().trim();
    if (!useMemoryFallback && db) {
      const stmt = db.prepare('SELECT * FROM users WHERE email = ? AND is_active = 1');
      return stmt.get(normalized) as any;
    }
    for (const u of memoryUsers.values()) {
      if (u.email === normalized && u.is_active === 1) return { ...u };
    }
    return undefined;
  },

  findAnyByEmail: (email: string) => {
    const normalized = email.toLowerCase().trim();
    if (!useMemoryFallback && db) {
      const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
      return stmt.get(normalized) as any;
    }
    for (const u of memoryUsers.values()) {
      if (u.email === normalized) return { ...u };
    }
    return undefined;
  },

  findById: (id: string) => {
    if (!useMemoryFallback && db) {
      const stmt = db.prepare('SELECT * FROM users WHERE id = ? AND is_active = 1');
      return stmt.get(id) as any;
    }
    const u = memoryUsers.get(id);
    return u && u.is_active === 1 ? { ...u } : undefined;
  },

  findAnyById: (id: string) => {
    if (!useMemoryFallback && db) {
      const stmt = db.prepare('SELECT * FROM users WHERE id = ?');
      return stmt.get(id) as any;
    }
    const u = memoryUsers.get(id);
    return u ? { ...u } : undefined;
  },

  updateLastLogin: (id: string) => {
    const now = new Date().toISOString();
    if (!useMemoryFallback && db) {
      const stmt = db.prepare('UPDATE users SET last_login = ? WHERE id = ?');
      stmt.run(now, id);
      return;
    }
    const u = memoryUsers.get(id);
    if (u) u.last_login = now;
  },

  getAll: () => {
    if (!useMemoryFallback && db) {
      const stmt = db.prepare(`
        SELECT id, email, role, created_at, last_login, is_active, two_factor_enabled
        FROM users 
        ORDER BY created_at DESC
      `);
      return stmt.all();
    }
    return Array.from(memoryUsers.values())
      .map(({ password_hash, ...rest }) => rest)
      .sort((a, b) => b.created_at.localeCompare(a.created_at));
  },

  updateStatus: (id: string, isActive: boolean) => {
    if (!useMemoryFallback && db) {
      const stmt = db.prepare('UPDATE users SET is_active = ? WHERE id = ?');
      stmt.run(isActive ? 1 : 0, id);
      return;
    }
    const u = memoryUsers.get(id);
    if (u) u.is_active = isActive ? 1 : 0;
  },

  delete: (id: string) => {
    if (!useMemoryFallback && db) {
      const stmt = db.prepare('DELETE FROM users WHERE id = ?');
      stmt.run(id);
      return;
    }
    memoryUsers.delete(id);
  },

  getCount: () => {
    if (!useMemoryFallback && db) {
      const stmt = db.prepare('SELECT COUNT(*) as count FROM users WHERE is_active = 1');
      return stmt.get() as { count: number };
    }
    let count = 0;
    for (const u of memoryUsers.values()) {
      if (u.is_active === 1) count++;
    }
    return { count };
  },

  countActiveAdmins: () => {
    if (!useMemoryFallback && db) {
      const stmt = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'admin' AND is_active = 1");
      const result = stmt.get() as { count: number };
      return result.count;
    }
    let count = 0;
    for (const u of memoryUsers.values()) {
      if (u.role === 'admin' && u.is_active === 1) count++;
    }
    return count;
  },
};

// Session management operations
export const sessionDb = {
  create: (sessionId: string, userId: string, tokenHash: string, expiresAt: Date) => {
    const createdAt = new Date().toISOString();
    const expiresAtStr = expiresAt.toISOString();

    if (!useMemoryFallback && db) {
      const stmt = db.prepare(`
        INSERT INTO sessions (id, user_id, token_hash, expires_at, is_revoked, created_at)
        VALUES (?, ?, ?, ?, 0, ?)
      `);
      stmt.run(sessionId, userId, tokenHash, expiresAtStr, createdAt);
      return;
    }

    memorySessions.set(sessionId, {
      id: sessionId,
      user_id: userId,
      token_hash: tokenHash,
      expires_at: expiresAtStr,
      is_revoked: 0,
      created_at: createdAt,
    });
  },

  isValid: (sessionId: string, userId: string, tokenHash: string): boolean => {
    const now = new Date().toISOString();
    if (!useMemoryFallback && db) {
      const stmt = db.prepare(`
        SELECT id FROM sessions
        WHERE id = ? AND user_id = ? AND token_hash = ? AND is_revoked = 0 AND expires_at > ?
      `);
      const session = stmt.get(sessionId, userId, tokenHash, now);
      return !!session;
    }

    const session = memorySessions.get(sessionId);
    if (!session) return false;
    return (
      session.user_id === userId &&
      session.token_hash === tokenHash &&
      session.is_revoked === 0 &&
      session.expires_at > now
    );
  },

  revoke: (sessionId: string) => {
    if (!useMemoryFallback && db) {
      const stmt = db.prepare('UPDATE sessions SET is_revoked = 1 WHERE id = ?');
      stmt.run(sessionId);
      return;
    }
    const s = memorySessions.get(sessionId);
    if (s) s.is_revoked = 1;
  },

  revokeAllForUser: (userId: string) => {
    if (!useMemoryFallback && db) {
      const stmt = db.prepare('UPDATE sessions SET is_revoked = 1 WHERE user_id = ?');
      stmt.run(userId);
      return;
    }
    for (const s of memorySessions.values()) {
      if (s.user_id === userId) s.is_revoked = 1;
    }
  },

  cleanupExpired: () => {
    const now = new Date().toISOString();
    if (!useMemoryFallback && db) {
      const stmt = db.prepare('DELETE FROM sessions WHERE expires_at < ? OR is_revoked = 1');
      stmt.run(now);
      return;
    }
    for (const [id, s] of memorySessions.entries()) {
      if (s.expires_at < now || s.is_revoked === 1) {
        memorySessions.delete(id);
      }
    }
  },
};

// Password history operations
export const passwordHistoryDb = {
  add: (userId: string, analysis: any) => {
    const id = uuidv4();
    const createdAt = new Date().toISOString();

    if (!useMemoryFallback && db) {
      const stmt = db.prepare(`
        INSERT INTO password_history (id, user_id, strength_score, strength_level, entropy, is_breached, breach_count, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        id,
        userId,
        analysis.score,
        analysis.strength,
        analysis.entropy,
        analysis.isBreached ? 1 : 0,
        analysis.breachCount || 0,
        createdAt
      );
      return id;
    }

    memoryPasswordHistory.push({
      id,
      user_id: userId,
      password_hash: null,
      strength_score: analysis.score,
      strength_level: analysis.strength,
      entropy: analysis.entropy,
      is_breached: analysis.isBreached ? 1 : 0,
      breach_count: analysis.breachCount || 0,
      created_at: createdAt,
    });
    return id;
  },

  getByUser: (userId: string) => {
    if (!useMemoryFallback && db) {
      const stmt = db.prepare(`
        SELECT id, user_id, strength_score, strength_level, entropy, is_breached, breach_count, created_at 
        FROM password_history 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 10
      `);
      return stmt.all(userId) as any[];
    }

    return memoryPasswordHistory
      .filter((h) => h.user_id === userId)
      .sort((a, b) => b.created_at.localeCompare(a.created_at))
      .slice(0, 10);
  },
};

// Password checks operations
export const passwordCheckDb = {
  log: (userId: string | null, analysis: any, ipAddress?: string, userAgent?: string) => {
    const id = uuidv4();
    const createdAt = new Date().toISOString();

    if (!useMemoryFallback && db) {
      const stmt = db.prepare(`
        INSERT INTO password_checks (id, user_id, strength_score, strength_level, entropy, is_breached, breach_count, ip_address, user_agent, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        id,
        userId,
        analysis.score,
        analysis.strength,
        analysis.entropy,
        analysis.isBreached ? 1 : 0,
        analysis.breachCount || 0,
        ipAddress || null,
        userAgent || null,
        createdAt
      );
      return id;
    }

    memoryPasswordChecks.push({
      id,
      user_id: userId,
      password_hash: null,
      strength_score: analysis.score,
      strength_level: analysis.strength,
      entropy: analysis.entropy,
      is_breached: analysis.isBreached ? 1 : 0,
      breach_count: analysis.breachCount || 0,
      ip_address: ipAddress || null,
      user_agent: userAgent || null,
      created_at: createdAt,
    });
    return id;
  },

  getCount: () => {
    if (!useMemoryFallback && db) {
      const stmt = db.prepare('SELECT COUNT(*) as count FROM password_checks');
      return stmt.get() as { count: number };
    }
    return { count: memoryPasswordChecks.length };
  },

  getBreachedCount: () => {
    if (!useMemoryFallback && db) {
      const stmt = db.prepare('SELECT COUNT(*) as count FROM password_checks WHERE is_breached = 1');
      return stmt.get() as { count: number };
    }
    const count = memoryPasswordChecks.filter((c) => c.is_breached === 1).length;
    return { count };
  },

  getAverageStrength: () => {
    if (!useMemoryFallback && db) {
      const stmt = db.prepare('SELECT AVG(strength_score) as average FROM password_checks');
      const result = stmt.get() as { average: number };
      return Math.round(result.average || 0);
    }
    if (memoryPasswordChecks.length === 0) return 0;
    const sum = memoryPasswordChecks.reduce((acc, c) => acc + c.strength_score, 0);
    return Math.round(sum / memoryPasswordChecks.length);
  },

  getStrengthDistribution: () => {
    if (!useMemoryFallback && db) {
      const stmt = db.prepare(`
        SELECT strength_level, COUNT(*) as count 
        FROM password_checks 
        GROUP BY strength_level
      `);
      return stmt.all();
    }
    const counts: Record<string, number> = {};
    for (const c of memoryPasswordChecks) {
      counts[c.strength_level] = (counts[c.strength_level] || 0) + 1;
    }
    return Object.entries(counts).map(([strength_level, count]) => ({ strength_level, count }));
  },
};

// Login attempts operations
export const loginAttemptsDb = {
  log: (email: string, success: boolean, ipAddress?: string, userAgent?: string, failureReason?: string) => {
    const id = uuidv4();
    const createdAt = new Date().toISOString();

    if (!useMemoryFallback && db) {
      const stmt = db.prepare(`
        INSERT INTO login_attempts (id, email, success, ip_address, user_agent, failure_reason, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        id,
        email.toLowerCase().trim(),
        success ? 1 : 0,
        ipAddress || null,
        userAgent || null,
        failureReason || null,
        createdAt
      );
      return;
    }

    memoryLoginAttempts.push({
      id,
      email: email.toLowerCase().trim(),
      success: success ? 1 : 0,
      ip_address: ipAddress || null,
      user_agent: userAgent || null,
      failure_reason: failureReason || null,
      created_at: createdAt,
    });
  },

  getRecentFailedAttemptsByEmail: (email: string, minutes: number = 15) => {
    const since = new Date(Date.now() - minutes * 60 * 1000).toISOString();
    const normalized = email.toLowerCase().trim();

    if (!useMemoryFallback && db) {
      const stmt = db.prepare(`
        SELECT COUNT(*) as count 
        FROM login_attempts 
        WHERE email = ? AND success = 0 AND created_at > ?
      `);
      return stmt.get(normalized, since) as { count: number };
    }

    const count = memoryLoginAttempts.filter(
      (a) => a.email === normalized && a.success === 0 && a.created_at > since
    ).length;
    return { count };
  },

  getRecentFailedAttemptsByIp: (ipAddress: string, minutes: number = 15) => {
    const since = new Date(Date.now() - minutes * 60 * 1000).toISOString();

    if (!useMemoryFallback && db) {
      const stmt = db.prepare(`
        SELECT COUNT(*) as count 
        FROM login_attempts 
        WHERE ip_address = ? AND success = 0 AND created_at > ?
      `);
      return stmt.get(ipAddress, since) as { count: number };
    }

    const count = memoryLoginAttempts.filter(
      (a) => a.ip_address === ipAddress && a.success === 0 && a.created_at > since
    ).length;
    return { count };
  },

  getRecentFailedAttemptsByIpAndEmail: (ipAddress: string, email: string, minutes: number = 15) => {
    const since = new Date(Date.now() - minutes * 60 * 1000).toISOString();
    const normalized = email.toLowerCase().trim();

    if (!useMemoryFallback && db) {
      const stmt = db.prepare(`
        SELECT COUNT(*) as count 
        FROM login_attempts 
        WHERE ip_address = ? AND email = ? AND success = 0 AND created_at > ?
      `);
      return stmt.get(ipAddress, normalized, since) as { count: number };
    }

    const count = memoryLoginAttempts.filter(
      (a) => a.ip_address === ipAddress && a.email === normalized && a.success === 0 && a.created_at > since
    ).length;
    return { count };
  },
};

// Admin audit log operations
export const adminAuditDb = {
  log: (
    adminId: string,
    adminEmail: string,
    action: string,
    targetType: string,
    targetId: string | null,
    details: string | null,
    ipAddress: string | null
  ) => {
    const id = uuidv4();
    const createdAt = new Date().toISOString();

    if (!useMemoryFallback && db) {
      const stmt = db.prepare(`
        INSERT INTO admin_audit_logs (id, admin_id, admin_email, action, target_type, target_id, details, ip_address, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(id, adminId, adminEmail, action, targetType, targetId, details, ipAddress, createdAt);
      return id;
    }

    memoryAdminAuditLogs.push({
      id,
      adminId,
      adminEmail,
      action,
      targetType,
      targetId,
      details,
      ipAddress,
      createdAt,
    });
    return id;
  },

  getAll: (limit: number = 50, offset: number = 0) => {
    if (!useMemoryFallback && db) {
      const stmt = db.prepare(`
        SELECT id, admin_id as adminId, admin_email as adminEmail, action, target_type as targetType, target_id as targetId, details, ip_address as ipAddress, created_at as createdAt
        FROM admin_audit_logs
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
      `);
      return stmt.all(limit, offset) as any[];
    }

    return memoryAdminAuditLogs
      .slice()
      .reverse()
      .slice(offset, offset + limit);
  },
};

export default db;
