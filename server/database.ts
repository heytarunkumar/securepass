import Database from 'better-sqlite3';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';

// Database connection
const db = new Database('securepass.db');

// Enable foreign keys
db.pragma('foreign_keys = ON');

// Create tables
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

  CREATE TABLE IF NOT EXISTS password_history (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    password_hash TEXT NOT NULL,
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
    password_hash TEXT NOT NULL,
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
    password_hash TEXT NOT NULL,
    breach_count INTEGER NOT NULL,
    notified INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// Create default admin user if doesn't exist
const checkAdmin = db.prepare('SELECT id FROM users WHERE email = ? AND role = ?');
const adminExists = checkAdmin.get('admin@securepass.com', 'admin');

if (!adminExists) {
  const adminPassword = 'SecurePass2024!';
  const hashedPassword = bcrypt.hashSync(adminPassword, 12);
  const insertAdmin = db.prepare(`
    INSERT INTO users (id, email, password_hash, role, created_at)
    VALUES (?, ?, ?, ?, ?)
  `);
  
  insertAdmin.run(uuidv4(), 'admin@securepass.com', hashedPassword, 'admin', new Date().toISOString());
  console.log('✅ Default admin created: admin@securepass.com / SecurePass2024!');
}

// User database operations
export const userDb = {
  // Create user
  create: (email: string, password: string, role: 'user' | 'admin' = 'user') => {
    const id = uuidv4();
    const hashedPassword = bcrypt.hashSync(password, 12);
    const stmt = db.prepare(`
      INSERT INTO users (id, email, password_hash, role, created_at)
      VALUES (?, ?, ?, ?, ?)
    `);
    
    try {
      stmt.run(id, email, hashedPassword, role, new Date().toISOString());
      return { id, email, role, created_at: new Date().toISOString() };
    } catch (error: any) {
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        throw new Error('Email already exists');
      }
      throw error;
    }
  },

  // Find user by email
  findByEmail: (email: string) => {
    const stmt = db.prepare('SELECT * FROM users WHERE email = ? AND is_active = 1');
    return stmt.get(email) as any;
  },

  // Find user by ID
  findById: (id: string) => {
    const stmt = db.prepare('SELECT * FROM users WHERE id = ? AND is_active = 1');
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
  }
};

// Password history operations
export const passwordHistoryDb = {
  // Add password to history
  add: (userId: string, passwordHash: string, analysis: any) => {
    const id = uuidv4();
    const stmt = db.prepare(`
      INSERT INTO password_history (id, user_id, password_hash, strength_score, strength_level, entropy, is_breached, breach_count, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    stmt.run(
      id, 
      userId, 
      passwordHash, 
      analysis.score, 
      analysis.strength, 
      analysis.entropy,
      analysis.isBreached ? 1 : 0,
      analysis.breachCount || 0,
      new Date().toISOString()
    );
    return id;
  },

  // Get user's password history
  getByUser: (userId: string) => {
    const stmt = db.prepare(`
      SELECT * FROM password_history 
      WHERE user_id = ? 
      ORDER BY created_at DESC 
      LIMIT 10
    `);
    return stmt.all(userId);
  }
};

// Password checks operations
export const passwordCheckDb = {
  // Log password check
  log: (userId: string | null, passwordHash: string, analysis: any, ipAddress?: string, userAgent?: string) => {
    const id = uuidv4();
    const stmt = db.prepare(`
      INSERT INTO password_checks (id, user_id, password_hash, strength_score, strength_level, entropy, is_breached, breach_count, ip_address, user_agent, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    stmt.run(
      id,
      userId,
      passwordHash,
      analysis.score,
      analysis.strength,
      analysis.entropy,
      analysis.isBreached ? 1 : 0,
      analysis.breachCount || 0,
      ipAddress,
      userAgent,
      new Date().toISOString()
    );
    return id;
  },

  // Get total checks count
  getCount: () => {
    const stmt = db.prepare('SELECT COUNT(*) as count FROM password_checks');
    return stmt.get() as { count: number };
  },

  // Get breached passwords count
  getBreachedCount: () => {
    const stmt = db.prepare('SELECT COUNT(*) as count FROM password_checks WHERE is_breached = 1');
    return stmt.get() as { count: number };
  },

  // Get average strength
  getAverageStrength: () => {
    const stmt = db.prepare('SELECT AVG(strength_score) as average FROM password_checks');
    const result = stmt.get() as { average: number };
    return Math.round(result.average || 0);
  },

  // Get strength distribution
  getStrengthDistribution: () => {
    const stmt = db.prepare(`
      SELECT strength_level, COUNT(*) as count 
      FROM password_checks 
      GROUP BY strength_level
    `);
    return stmt.all();
  }
};

// Login attempts operations
export const loginAttemptsDb = {
  // Log login attempt
  log: (email: string, success: boolean, ipAddress?: string, userAgent?: string, failureReason?: string) => {
    const id = uuidv4();
    const stmt = db.prepare(`
      INSERT INTO login_attempts (id, email, success, ip_address, user_agent, failure_reason, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    
    stmt.run(id, email, success ? 1 : 0, ipAddress, userAgent, failureReason, new Date().toISOString());
  },

  // Get recent failed attempts for an email
  getRecentFailedAttempts: (email: string, minutes: number = 15) => {
    const since = new Date(Date.now() - minutes * 60 * 1000).toISOString();
    const stmt = db.prepare(`
      SELECT COUNT(*) as count 
      FROM login_attempts 
      WHERE email = ? AND success = 0 AND created_at > ?
    `);
    return stmt.get(email, since) as { count: number };
  }
};

export default db;
