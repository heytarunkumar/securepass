import { RequestHandler } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { userDb, loginAttemptsDb, passwordHistoryDb, sessionDb } from '../database';
import {
  generateToken,
  comparePassword,
  hashPassword,
  hashToken,
  AuthRequest
} from '../auth';
import { RegistrationSchema, LoginSchema } from '../validation';
import { AuthResponse } from '@shared/api';

// SP-07: Rate limiting thresholds
const MAX_FAILED_PER_IP_AND_EMAIL = 5;
const MAX_FAILED_PER_IP = 25;
const THROTTLE_WINDOW_MINUTES = 15;

// Register new user (SP-11: Zod validation, async hashing, bounded inputs)
export const handleRegister: RequestHandler = async (req, res) => {
  try {
    const parseResult = RegistrationSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        message: parseResult.error.errors[0]?.message || 'Invalid input data',
      });
    }

    const { email, password } = parseResult.data;
    const normalizedEmail = email.toLowerCase().trim();

    // Check if account already exists
    const existing = userDb.findAnyByEmail(normalizedEmail);
    if (existing) {
      return res.status(409).json({
        success: false,
        message: 'An account with this email already exists',
      });
    }

    // Hash password asynchronously with 12 rounds
    const hashedPassword = await hashPassword(password);
    const user = userDb.create(normalizedEmail, hashedPassword, 'user');

    // Create session (SP-05: Server-side revocable session)
    const sessionId = uuidv4();
    const token = generateToken(
      {
        id: user.id,
        email: user.email,
        role: user.role as 'user' | 'admin',
      },
      sessionId
    );

    // Calculate expiration (1 hour from now)
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
    sessionDb.create(sessionId, user.id, hashToken(token), expiresAt);

    // Log successful registration
    loginAttemptsDb.log(
      normalizedEmail,
      true,
      req.ip,
      req.get('User-Agent')
    );

    const response: AuthResponse = {
      success: true,
      message: 'Account created successfully',
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role as 'user' | 'admin',
      },
    };

    res.status(201).json(response);
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during registration',
    });
  }
};

// Login user (SP-07: IP-aware and account-aware throttling, generic error messages)
export const handleLogin: RequestHandler = async (req, res) => {
  try {
    const parseResult = LoginSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        message: parseResult.error.errors[0]?.message || 'Email and password are required',
      });
    }

    const { email, password } = parseResult.data;
    const normalizedEmail = email.toLowerCase().trim();
    const clientIp = req.ip || 'unknown';

    // Check global IP throttle (prevents mass credential stuffing from single IP)
    const failedByIp = loginAttemptsDb.getRecentFailedAttemptsByIp(clientIp, THROTTLE_WINDOW_MINUTES);
    if (failedByIp.count >= MAX_FAILED_PER_IP) {
      loginAttemptsDb.log(normalizedEmail, false, clientIp, req.get('User-Agent'), 'IP throttled');
      return res.status(429).json({
        success: false,
        message: 'Too many requests from this location. Please try again later.',
      });
    }

    // Check (IP + Email) throttle (prevents attackers locking out victims from other IPs)
    const failedByIpAndEmail = loginAttemptsDb.getRecentFailedAttemptsByIpAndEmail(clientIp, normalizedEmail, THROTTLE_WINDOW_MINUTES);
    if (failedByIpAndEmail.count >= MAX_FAILED_PER_IP_AND_EMAIL) {
      loginAttemptsDb.log(normalizedEmail, false, clientIp, req.get('User-Agent'), 'Account+IP throttled');
      return res.status(429).json({
        success: false,
        message: 'Too many failed login attempts. Please try again in 15 minutes.',
      });
    }

    // Find user (active only)
    const user = userDb.findByEmail(normalizedEmail);
    if (!user) {
      loginAttemptsDb.log(normalizedEmail, false, clientIp, req.get('User-Agent'), 'Invalid credentials');
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password',
      });
    }

    // Check password asynchronously
    const isPasswordValid = await comparePassword(password, user.password_hash);
    if (!isPasswordValid) {
      loginAttemptsDb.log(normalizedEmail, false, clientIp, req.get('User-Agent'), 'Invalid credentials');
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password',
      });
    }

    // Update last login
    userDb.updateLastLogin(user.id);

    // Log successful login
    loginAttemptsDb.log(normalizedEmail, true, clientIp, req.get('User-Agent'));

    // Create session (SP-05: Server-side revocable session)
    const sessionId = uuidv4();
    const token = generateToken(
      {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      sessionId
    );

    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
    sessionDb.create(sessionId, user.id, hashToken(token), expiresAt);

    const response: AuthResponse = {
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    };

    res.json(response);
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during login',
    });
  }
};

// Get current user profile (SP-05, SP-12)
export const handleProfile: RequestHandler = async (req: AuthRequest, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
    }

    const user = userDb.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found or account deactivated',
      });
    }

    // Get password history (metadata only, no hashes)
    const passwordHistory = passwordHistoryDb.getByUser(user.id);

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        createdAt: user.created_at,
        lastLogin: user.last_login,
        twoFactorEnabled: false, // SP-12: Accurately reflected until real MFA is enrolled
        passwordHistory: passwordHistory.map((p) => ({
          id: p.id,
          strength: p.strength_level,
          score: p.strength_score,
          entropy: p.entropy,
          isBreached: p.is_breached === 1,
          breachCount: p.breach_count,
          createdAt: p.created_at,
        })),
      },
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Logout (SP-05: Server-side token and session revocation)
export const handleLogout: RequestHandler = async (req: AuthRequest, res) => {
  try {
    if (req.user?.sessionId) {
      sessionDb.revoke(req.user.sessionId);
    }

    res.json({
      success: true,
      message: 'Logged out successfully',
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during logout',
    });
  }
};
