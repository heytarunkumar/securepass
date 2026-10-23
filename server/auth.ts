import jwt, { SignOptions } from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import { Request, Response, NextFunction } from 'express';
import { userDb, sessionDb } from './database';

// SP-03: Cryptographically secure JWT Secret management with zero hardcoded production fallbacks
function getJwtSecret(): string {
  const envSecret = process.env.JWT_SECRET;
  const isProduction = process.env.NODE_ENV === 'production';

  if (!envSecret) {
    if (isProduction) {
      throw new Error('FATAL SECURITY ERROR (SP-03): JWT_SECRET is not set in production. Application startup aborted.');
    }
    // In development or test, generate an ephemeral cryptographically strong random secret
    if (!global.__DEV_JWT_SECRET) {
      global.__DEV_JWT_SECRET = crypto.randomBytes(32).toString('hex');
      console.warn('⚠️ [DEV WARNING (SP-03)]: No JWT_SECRET specified. Generated an ephemeral cryptographically secure random key for development.');
    }
    return global.__DEV_JWT_SECRET;
  }

  if (envSecret.length < 32) {
    if (isProduction) {
      throw new Error('FATAL SECURITY ERROR (SP-03): JWT_SECRET must be at least 32 characters in production.');
    }
    console.warn('⚠️ [DEV WARNING (SP-03)]: JWT_SECRET is less than 32 characters. Consider increasing secret entropy.');
  }

  return envSecret;
}

declare global {
  // eslint-disable-next-line no-var
  var __DEV_JWT_SECRET: string | undefined;
}

// SP-03 & SP-14: Short-lived access tokens (default 1h instead of 7 days)
const JWT_EXPIRES_IN = (process.env.JWT_EXPIRES_IN || '1h') as any;

export interface AuthUser {
  id: string;
  email: string;
  role: 'user' | 'admin';
  sessionId?: string;
}

export interface AuthRequest extends Request {
  user?: AuthUser;
  token?: string;
}

// Hash token for safe database session indexing
export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Generate JWT token with embedded session ID (SP-05: Revocable tokens)
export const generateToken = (user: AuthUser, sessionId: string): string => {
  const secret = getJwtSecret();
  const options: SignOptions = {
    expiresIn: JWT_EXPIRES_IN,
    jwtid: sessionId,
  };

  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      sessionId,
    },
    secret,
    options
  );
};

// Verify JWT token signature and expiration
export const verifyToken = (token: string): AuthUser => {
  const secret = getJwtSecret();
  try {
    const decoded = jwt.verify(token, secret) as any;
    return {
      id: decoded.id,
      email: decoded.email,
      role: decoded.role,
      sessionId: decoded.sessionId || decoded.jti,
    };
  } catch (error) {
    throw new Error('Invalid or expired token');
  }
};

// Hash password with bcrypt at 12 rounds
export const hashPassword = async (password: string): Promise<string> => {
  return bcrypt.hash(password, 12);
};

// Compare password
export const comparePassword = async (password: string, hash: string): Promise<boolean> => {
  return bcrypt.compare(password, hash);
};

// Middleware to authenticate requests (SP-05: Real-time DB lookup and session revocation check)
export const authenticateToken = (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;

  if (!token) {
    return res.status(401).json({ success: false, error: 'Access token required' });
  }

  try {
    const decoded = verifyToken(token);

    // SP-05: Look up current user in database to enforce active account status immediately
    const dbUser = userDb.findById(decoded.id);
    if (!dbUser || dbUser.is_active !== 1) {
      return res.status(403).json({ success: false, error: 'Account has been deactivated or does not exist' });
    }

    // SP-05: Validate server-side session
    if (decoded.sessionId) {
      const tokenDigest = hashToken(token);
      const isSessionValid = sessionDb.isValid(decoded.sessionId, decoded.id, tokenDigest);
      if (!isSessionValid) {
        return res.status(401).json({ success: false, error: 'Session has expired or was revoked' });
      }
    }

    // Set fresh authenticated user with latest role from DB
    req.user = {
      id: dbUser.id,
      email: dbUser.email,
      role: dbUser.role as 'user' | 'admin',
      sessionId: decoded.sessionId,
    };
    req.token = token;

    next();
  } catch (error) {
    return res.status(403).json({ success: false, error: 'Invalid or expired token' });
  }
};

// Middleware to check if user is admin (SP-05: Uses current role from DB)
export const requireAdmin = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (!req.user) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }

  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, error: 'Admin access required' });
  }

  next();
};

// Middleware for optional authentication
export const optionalAuth = (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;

  if (token) {
    try {
      const decoded = verifyToken(token);
      const dbUser = userDb.findById(decoded.id);
      if (dbUser && dbUser.is_active === 1) {
        if (!decoded.sessionId || sessionDb.isValid(decoded.sessionId, decoded.id, hashToken(token))) {
          req.user = {
            id: dbUser.id,
            email: dbUser.email,
            role: dbUser.role as 'user' | 'admin',
            sessionId: decoded.sessionId,
          };
          req.token = token;
        }
      }
    } catch (error) {
      // Token is invalid/expired, continue unauthenticated
    }
  }

  next();
};
