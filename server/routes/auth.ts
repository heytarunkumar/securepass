import { RequestHandler } from "express";
import { userDb, loginAttemptsDb, passwordHistoryDb } from "../database";
import { 
  generateToken, 
  comparePassword, 
  validatePassword, 
  checkRateLimit,
  AuthRequest
} from "../auth";
import { 
  UserRegistrationRequest, 
  UserLoginRequest, 
  AuthResponse 
} from "@shared/api";

// Register new user
export const handleRegister: RequestHandler = async (req, res) => {
  try {
    const { email, password, confirmPassword } = req.body as UserRegistrationRequest;

    // Validate input
    if (!email || !password || !confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Email, password, and password confirmation are required'
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Passwords do not match'
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Please enter a valid email address'
      });
    }

    // Validate password strength
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      return res.status(400).json({
        success: false,
        message: passwordValidation.message
      });
    }

    // Create user
    try {
      const user = userDb.create(email.toLowerCase(), password);
      const token = generateToken({
        id: user.id,
        email: user.email,
        role: user.role as 'user' | 'admin'
      });

      // Log successful registration
      loginAttemptsDb.log(
        email.toLowerCase(), 
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
          role: user.role as 'user' | 'admin'
        }
      };

      res.status(201).json(response);
    } catch (error: any) {
      if (error.message === 'Email already exists') {
        return res.status(409).json({
          success: false,
          message: 'An account with this email already exists'
        });
      }
      throw error;
    }
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during registration'
    });
  }
};

// Login user
export const handleLogin: RequestHandler = async (req, res) => {
  try {
    const { email, password } = req.body as UserLoginRequest;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    const normalizedEmail = email.toLowerCase();

    // Check rate limiting
    const recentFailedAttempts = loginAttemptsDb.getRecentFailedAttempts(normalizedEmail);
    if (!checkRateLimit(recentFailedAttempts.count)) {
      loginAttemptsDb.log(
        normalizedEmail, 
        false, 
        req.ip, 
        req.get('User-Agent'), 
        'Rate limited'
      );
      
      return res.status(429).json({
        success: false,
        message: 'Too many failed login attempts. Please try again in 15 minutes.'
      });
    }

    // Find user
    const user = userDb.findByEmail(normalizedEmail);
    if (!user) {
      loginAttemptsDb.log(
        normalizedEmail, 
        false, 
        req.ip, 
        req.get('User-Agent'), 
        'User not found'
      );
      
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Check password
    const isPasswordValid = await comparePassword(password, user.password_hash);
    if (!isPasswordValid) {
      loginAttemptsDb.log(
        normalizedEmail, 
        false, 
        req.ip, 
        req.get('User-Agent'), 
        'Invalid password'
      );
      
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Update last login
    userDb.updateLastLogin(user.id);

    // Log successful login
    loginAttemptsDb.log(
      normalizedEmail, 
      true, 
      req.ip, 
      req.get('User-Agent')
    );

    // Generate token
    const token = generateToken({
      id: user.id,
      email: user.email,
      role: user.role
    });

    const response: AuthResponse = {
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role
      }
    };

    res.json(response);
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during login'
    });
  }
};

// Get current user profile
export const handleProfile: RequestHandler = async (req: AuthRequest, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    const user = userDb.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Get password history
    const passwordHistory = passwordHistoryDb.getByUser(user.id);

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        createdAt: user.created_at,
        lastLogin: user.last_login,
        twoFactorEnabled: user.two_factor_enabled === 1,
        passwordHistory: passwordHistory.map(p => ({
          id: p.id,
          strength: p.strength_level,
          score: p.strength_score,
          entropy: p.entropy,
          isBreached: p.is_breached === 1,
          breachCount: p.breach_count,
          createdAt: p.created_at
        }))
      }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

// Logout (client-side token removal, but we can log it)
export const handleLogout: RequestHandler = async (req: AuthRequest, res) => {
  try {
    // In a real app, you might want to blacklist the token
    // For now, we just return success since JWT is stateless
    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};
