import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { handleDemo } from './routes/demo';
import { handlePasswordAnalysis } from './routes/password-analysis';
import { handleRegister, handleLogin, handleProfile, handleLogout } from './routes/auth';
import {
  handleAdminStats,
  handleGetUsers,
  handleUpdateUserStatus,
  handleDeleteUser,
  handleGetUserDetails,
  handleGetAuditLogs,
} from './routes/admin';
import { authenticateToken, requireAdmin, optionalAuth } from './auth';
import './database'; // Initialize database schema & safe migrations

export function createServer() {
  const app = express();

  // SP-07: Enable trust proxy for accurate client IP resolution behind reverse proxies (Vercel, Cloudflare, etc.)
  app.set('trust proxy', 1);

  // SP-09: Defense-in-depth Security Headers Middleware
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '0');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

    // Strict Content Security Policy
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https:; connect-src 'self' https://api.pwnedpasswords.com;"
    );

    if (process.env.NODE_ENV === 'production') {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }

    next();
  });

  // SP-09: Configured CORS with explicit origin allowlist
  const configuredOrigins = process.env.CORS_ORIGIN
    ? process.env.CORS_ORIGIN.split(',').map((o) => o.trim())
    : [
        'http://localhost:8080',
        'http://localhost:5173',
        'http://127.0.0.1:8080',
        'http://127.0.0.1:5173',
      ];

  app.use(
    cors({
      origin: (origin, callback) => {
        // Allow requests with no origin (e.g. mobile apps, curl, same-origin)
        if (!origin) return callback(null, true);

        // Check if origin matches configured allowed origins
        const isAllowed = configuredOrigins.some((allowed) => {
          if (allowed === '*' && process.env.NODE_ENV !== 'production') return true;
          return origin === allowed || allowed.endsWith(origin);
        });

        if (isAllowed || process.env.NODE_ENV !== 'production') {
          return callback(null, true);
        }

        return callback(new Error('CORS policy: Not allowed by CORS configuration'));
      },
      methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization'],
      credentials: true,
      maxAge: 86400,
    })
  );

  // SP-08: Explicit request body size limits to prevent memory exhaustion and DoS
  app.use(express.json({ limit: '16kb' }));
  app.use(express.urlencoded({ extended: true, limit: '16kb' }));

  // API routes
  app.get('/api/ping', (_req, res) => {
    const ping = process.env.PING_MESSAGE ?? 'ping';
    res.json({ message: ping });
  });

  app.get('/api/demo', handleDemo);

  // Password analysis (with optional auth for personal history saving)
  app.post('/api/password-analysis', optionalAuth, handlePasswordAnalysis);

  // Authentication routes
  app.post('/api/auth/register', handleRegister);
  app.post('/api/auth/login', handleLogin);
  app.get('/api/auth/profile', authenticateToken, handleProfile);
  app.post('/api/auth/logout', authenticateToken, handleLogout);

  // Admin routes
  app.get('/api/admin/stats', authenticateToken, requireAdmin, handleAdminStats);
  app.get('/api/admin/users', authenticateToken, requireAdmin, handleGetUsers);
  app.get('/api/admin/users/:userId', authenticateToken, requireAdmin, handleGetUserDetails);
  app.patch('/api/admin/users/:userId/status', authenticateToken, requireAdmin, handleUpdateUserStatus);
  app.delete('/api/admin/users/:userId', authenticateToken, requireAdmin, handleDeleteUser);
  app.get('/api/admin/audit-logs', authenticateToken, requireAdmin, handleGetAuditLogs);

  return app;
}
