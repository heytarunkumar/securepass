# Deployment Guide for SecurePass Password Checker

## Current Architecture
This application is built as a full-stack Node.js application with:
- **Frontend**: React + Vite + Tailwind CSS
- **Backend**: Express.js server with SQLite database
- **Authentication**: JWT tokens with bcrypt password hashing
- **APIs**: RESTful endpoints for user management and password analysis

## Deployment Options

### 🎯 Option 1: Persistent Node.js Deployment (RECOMMENDED FOR SQLITE)

For deployments using SQLite, deploy to platforms with persistent disk volumes so data is not wiped between restarts:

#### Railway (Recommended for Persistent SQLite)
```bash
# 1. Install Railway CLI
npm install -g @railway/cli

# 2. Login and deploy
railway login
railway up

# 3. Add volume mount at /app/data and set DATABASE_PATH=/app/data/securepass.db
# 4. Set required production environment variables:
# JWT_SECRET=<generate-at-least-32-random-characters>
# NODE_ENV=production
# 5. Provision the initial administrator:
# ADMIN_BOOTSTRAP_EMAIL=admin@yourdomain.com ADMIN_BOOTSTRAP_PASSWORD=<strong-password> npm run bootstrap:admin
```

#### Render / Fly.io / VPS
1. Connect repository or deploy container.
2. Set build command: `npm run build`
3. Set start command: `npm start`
4. Attach a persistent disk volume to ensure SQLite durability.
5. Set environment variables (`JWT_SECRET`, `NODE_ENV=production`).

### ⚠️ Option 2: Serverless Platforms (Vercel)

> **Important Architecture Notice (SP-06)**:
> In serverless environments like Vercel, the local filesystem (`/tmp`) is ephemeral and stateless. Data written to `/tmp/securepass.db` will not persist across cold starts or concurrent lambdas.
> For production on Vercel, connect to an external managed database (e.g. Neon PostgreSQL, Supabase, PlanetScale).

```bash
# 1. Install Vercel CLI
npm i -g vercel

# 2. Set environment variables in Vercel project dashboard:
# JWT_SECRET=<at-least-32-cryptographic-characters>
# NODE_ENV=production
# CORS_ORIGIN=https://your-domain.vercel.app

# 3. Deploy
vercel --prod
```

### 🔄 Option 2: Netlify with Serverless Functions

To deploy on Netlify, you'll need to convert the backend to serverless functions:

#### Required Changes:
1. **Convert Express routes to Netlify Functions**
2. **Replace SQLite with external database** (PlanetScale, Supabase, etc.)
3. **Update API calls** to use function endpoints

#### Example Netlify Function (netlify/functions/auth.js):
```javascript
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

exports.handler = async (event, context) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  try {
    const { email, password } = JSON.parse(event.body);
    
    // Database operations would use external service
    // Authentication logic here
    
    return {
      statusCode: 200,
      body: JSON.stringify({ success: true, token: 'jwt-token' })
    };
  } catch (error) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal server error' })
    };
  }
};
```

### 🗄️ Option 3: Database Alternatives

For production deployment, consider these database options:

#### External Database Services:
- **Supabase** - PostgreSQL with built-in auth
- **PlanetScale** - Serverless MySQL
- **MongoDB Atlas** - Cloud MongoDB
- **Turso** - Serverless SQLite (libSQL)

### 📋 Environment Variables for Production

```env
# Required for all deployments
JWT_SECRET=your-super-secure-production-secret-key
NODE_ENV=production
JWT_EXPIRES_IN=7d

# Database (if using external service)
DATABASE_URL=your-database-connection-string

# Optional
BCRYPT_ROUNDS=12
```

## Quick Deploy Commands

### For Vercel:
```bash
npm run build
vercel --prod
```

### For Railway:
```bash
git push railway main
```

### For Render:
1. Connect GitHub repo
2. Auto-deploys on git push

## Current File Structure
```
├── client/          # React frontend
├── server/          # Express.js backend
├── shared/          # Shared TypeScript types
├── securepass.db    # SQLite database (auto-created)
└── package.json     # Dependencies and scripts
```

## Production Checklist

- [ ] Set secure JWT_SECRET in production
- [ ] Configure HTTPS/SSL
- [ ] Set up database backups
- [ ] Configure rate limiting
- [ ] Set up monitoring/logging
- [ ] Configure CORS for production domain
- [ ] Test all authentication flows
- [ ] Verify password breach detection works

## Recommended: Deploy to Vercel

Vercel is the best choice because:
- ✅ Supports full Node.js applications
- ✅ Automatic HTTPS
- ✅ Easy environment variable management
- ✅ Git-based deployments
- ✅ Serverless functions for scalability
- ✅ Built-in CDN and caching
