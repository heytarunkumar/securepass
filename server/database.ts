import Database from 'better-sqlite3';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';
import { join } from 'path';

// Database connection & ephemeral serverless warnings
const isVercel = process.env.VERCEL === '1';
const dbPath = isVercel ? join('/tmp', 'securepass.db') : (process.env.DATABASE_PATH || 'securepass.db');

if (isVercel && process.env.NODE_ENV === 'production') {
  console.warn(
    '⚠️ [ARCHITECTURE WARNING (SP-06)]: Running SQLite database on Vercel ephemeral /tmp storage. ' +
    'Data will not persist across lambda invocations or deployments. ' +
    'Deploy to a persistent host (e.g. Railway, Render, VPS) or configure a managed database for production durability.'
  );
}

const db = new Database(dbPath);

// Enable foreign keys
db.pragma('foreign_keys = ON');

// Create tables with security hardening
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

// Migration helper: If existing tables had NOT NULL password_hash, migrate them safely
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
    console.warn('⚠️ [SECURITY REMEDIATION (SP-01)]: Purged vulnerable default admin account. Use bootstrap-admin command with a secure secret.');
  }
} catch (e) {
  // Ignore
}

// User database operations
export const userDb = {
  // Create user
  create: (email: string, passwordHash: string, role: 'user' | 'admin' = 'user') => {
    const id = uuidv4();
    const createdAt = new Date().toISOString();
    const stmt = db.prepare(`
      INSERT INTO users (id, email, password_hash, role, created_at)
      VALUES (?, ?, ?, ?, ?)
    `);

    try {
      stmt.run(id, email.toLowerCase().trim(), passwordHash, role, createdAt);
      return { id, email: email.toLowerCase().trim(), role, created_at: createdAt };
    } catch (error: any) {
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        throw new Error('Email already exists');
      }
      throw error;
    }
  },

  // Find user by email (active only)
  findByEmail: (email: string) => {
    const stmt = db.prepare('SELECT * FROM users WHERE email = ? AND is_active = 1');
    return stmt.get(email.toLowerCase().trim()) as any;
  },

  // Find user by email regardless of active status (for registration check)
  findAnyByEmail: (email: string) => {
    const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
    return stmt.get(email.toLowerCase().trim()) as any;
  },

  // Find user by ID (active only)
  findById: (id: string) => {
    const stmt = db.prepare('SELECT * FROM users WHERE id = ? AND is_active = 1');
    return stmt.get(id) as any;
  },

  // Find user by ID regardless of status
  findAnyById: (id: string) => {
    const stmt = db.prepare('SELECT * FROM users WHERE id = ?');
    return stmt.get(id) as any;
  },

  // Update last login
  updateLastLogin: (id: string) => {
    const stmt = db.prepare('UPDATE users SET last_login = ? WHERE id = ?');
    stmt.run(new Date().toISOString(), id);
  },

  // Get all users (admin only)
  getAll: () => {
    const stmt = db.prepare(`
      SELECT id, email, role, created_at, last_login, is_active, two_factor_enabled
      FROM users 
      ORDER BY created_at DESC
    `);
    return stmt.all();
  },

  // Update user status
  updateStatus: (id: string, isActive: boolean) => {
    const stmt = db.prepare('UPDATE users SET is_active = ? WHERE id = ?');
    stmt.run(isActive ? 1 : 0, id);
  },

  // Delete user
  delete: (id: string) => {
    const stmt = db.prepare('DELETE FROM users WHERE id = ?');
    stmt.run(id);
  },

  // Get user count
  getCount: () => {
    const stmt = db.prepare('SELECT COUNT(*) as count FROM users WHERE is_active = 1');
    return stmt.get() as { count: number };
  },

  // Count active administrators (SP-13: safeguard against deactivating last admin)
  countActiveAdmins: () => {
    const stmt = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'admin' AND is_active = 1");
    const result = stmt.get() as { count: number };
    return result.count;
  }
};

// Session management operations (SP-05: server-side token revocation & session management)
export const sessionDb = {
  create: (sessionId: string, userId: string, tokenHash: string, expiresAt: Date) => {
    const stmt = db.prepare(`
      INSERT INTO sessions (id, user_id, token_hash, expires_at, is_revoked, created_at)
      VALUES (?, ?, ?, ?, 0, ?)
    `);
    stmt.run(sessionId, userId, tokenHash, expiresAt.toISOString(), new Date().toISOString());
  },

  isValid: (sessionId: string, userId: string, tokenHash: string): boolean => {
    const stmt = db.prepare(`
      SELECT id FROM sessions
      WHERE id = ? AND user_id = ? AND token_hash = ? AND is_revoked = 0 AND expires_at > ?
    `);
    const session = stmt.get(sessionId, userId, tokenHash, new Date().toISOString());
    return !!session;
  },

  revoke: (sessionId: string) => {
    const stmt = db.prepare('UPDATE sessions SET is_revoked = 1 WHERE id = ?');
    stmt.run(sessionId);
  },

  revokeAllForUser: (userId: string) => {
    const stmt = db.prepare('UPDATE sessions SET is_revoked = 1 WHERE user_id = ?');
    stmt.run(userId);
  },

  cleanupExpired: () => {
    const stmt = db.prepare('DELETE FROM sessions WHERE expires_at < ? OR is_revoked = 1');
    stmt.run(new Date().toISOString());
  }
};

// Password history operations (SP-02: Never stores passwords or password hashes)
export const passwordHistoryDb = {
  add: (userId: string, analysis: any) => {
    const id = uuidv4();
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
      new Date().toISOString()
    );
    return id;
  },

  getByUser: (userId: string) => {
    const stmt = db.prepare(`
      SELECT id, user_id, strength_score, strength_level, entropy, is_breached, breach_count, created_at 
      FROM password_history 
      WHERE user_id = ? 
      ORDER BY created_at DESC 
      LIMIT 10
    `);
    return stmt.all(userId) as any[];
  }
};

// Password checks operations (SP-02 & SP-08: Metadata-only analytics, bounded storage)
export const passwordCheckDb = {
  log: (userId: string | null, analysis: any, ipAddress?: string, userAgent?: string) => {
    const id = uuidv4();
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
      new Date().toISOString()
    );
    return id;
  },

  getCount: () => {
    const stmt = db.prepare('SELECT COUNT(*) as count FROM password_checks');
    return stmt.get() as { count: number };
  },

  getBreachedCount: () => {
    const stmt = db.prepare('SELECT COUNT(*) as count FROM password_checks WHERE is_breached = 1');
    return stmt.get() as { count: number };
  },

  getAverageStrength: () => {
    const stmt = db.prepare('SELECT AVG(strength_score) as average FROM password_checks');
    const result = stmt.get() as { average: number };
    return Math.round(result.average || 0);
  },

  getStrengthDistribution: () => {
    const stmt = db.prepare(`
      SELECT strength_level, COUNT(*) as count 
      FROM password_checks 
      GROUP BY strength_level
    `);
    return stmt.all();
  }
};

// Login attempts operations (SP-07: IP-aware and account-aware throttling)
export const loginAttemptsDb = {
  log: (email: string, success: boolean, ipAddress?: string, userAgent?: string, failureReason?: string) => {
    const id = uuidv4();
    const stmt = db.prepare(`
      INSERT INTO login_attempts (id, email, success, ip_address, user_agent, failure_reason, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(id, email.toLowerCase().trim(), success ? 1 : 0, ipAddress || null, userAgent || null, failureReason || null, new Date().toISOString());
  },

  getRecentFailedAttemptsByEmail: (email: string, minutes: number = 15) => {
    const since = new Date(Date.now() - minutes * 60 * 1000).toISOString();
    const stmt = db.prepare(`
      SELECT COUNT(*) as count 
      FROM login_attempts 
      WHERE email = ? AND success = 0 AND created_at > ?
    `);
    return stmt.get(email.toLowerCase().trim(), since) as { count: number };
  },

  getRecentFailedAttemptsByIp: (ipAddress: string, minutes: number = 15) => {
    const since = new Date(Date.now() - minutes * 60 * 1000).toISOString();
    const stmt = db.prepare(`
      SELECT COUNT(*) as count 
      FROM login_attempts 
      WHERE ip_address = ? AND success = 0 AND created_at > ?
    `);
    return stmt.get(ipAddress, since) as { count: number };
  },

  getRecentFailedAttemptsByIpAndEmail: (ipAddress: string, email: string, minutes: number = 15) => {
    const since = new Date(Date.now() - minutes * 60 * 1000).toISOString();
    const stmt = db.prepare(`
      SELECT COUNT(*) as count 
      FROM login_attempts 
      WHERE ip_address = ? AND email = ? AND success = 0 AND created_at > ?
    `);
    return stmt.get(ipAddress, email.toLowerCase().trim(), since) as { count: number };
  }
};

// Admin audit log operations (SP-13: Comprehensive append-only audit trail)
export const adminAuditDb = {
  log: (adminId: string, adminEmail: string, action: string, targetType: string, targetId: string | null, details: string | null, ipAddress: string | null) => {
    const id = uuidv4();
    const stmt = db.prepare(`
      INSERT INTO admin_audit_logs (id, admin_id, admin_email, action, target_type, target_id, details, ip_address, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(id, adminId, adminEmail, action, targetType, targetId, details, ipAddress, new Date().toISOString());
    return id;
  },

  getAll: (limit: number = 50, offset: number = 0) => {
    const stmt = db.prepare(`
      SELECT id, admin_id as adminId, admin_email as adminEmail, action, target_type as targetType, target_id as targetId, details, ip_address as ipAddress, created_at as createdAt
      FROM admin_audit_logs
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `);
    return stmt.all(limit, offset) as any[];
  }
};

export default db;
