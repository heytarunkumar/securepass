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
  const rawOrigins = process.env.CORS_ORIGIN
    ? process.env.CORS_ORIGIN.split(',').map((o) => o.trim())
    : [];

  const defaultAllowedOrigins = [
    'http://localhost:8080',
    'http://localhost:5173',
    'http://127.0.0.1:8080',
    'http://127.0.0.1:5173',
  ];

  if (process.env.VERCEL_URL) {
    defaultAllowedOrigins.push(`https://${process.env.VERCEL_URL}`);
  }
  if (process.env.VERCEL_PROJECT_PRODUCTION_URL) {
    defaultAllowedOrigins.push(`https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`);
  }

  const allowedOrigins = new Set([...defaultAllowedOrigins, ...rawOrigins]);

  function isOriginAllowed(origin: string): boolean {
    if (!origin) return true;
    if (process.env.NODE_ENV !== 'production') return true;
    if (allowedOrigins.has(origin) || allowedOrigins.has('*')) return true;

    try {
      const parsed = new URL(origin);
      // Allow localhost or 127.0.0.1 on any port
      if (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1') return true;
      // Allow any Vercel or Netlify preview/production deployment domain
      if (parsed.hostname.endsWith('.vercel.app') || parsed.hostname.endsWith('.netlify.app')) return true;
    } catch {
      return false;
    }

    return false;
  }

  app.use(
    cors({
      origin: (origin, callback) => {
        if (!origin || isOriginAllowed(origin)) {
          return callback(null, true);
        }
        // Non-crashing CORS rejection: do not return Error (which crashes with 500)
        return callback(null, false);
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

  // Global error handler to ensure clean JSON responses
  app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error('Unhandled server error:', err);
    res.status(err.status || 500).json({ error: err.message || 'Internal server error' });
  });

  return app;
}
