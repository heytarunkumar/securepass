# Deployment Guide for SecurePass Password Checker

## Current Architecture
This application is built as a full-stack Node.js application with:
- **Frontend**: React + Vite + Tailwind CSS
- **Backend**: Express.js server with SQLite database
- **Authentication**: JWT tokens with bcrypt password hashing
- **APIs**: RESTful endpoints for user management and password analysis

## Deployment Options

### 🎯 Option 1: Full-Stack Deployment (RECOMMENDED)

Deploy the entire application as-is to platforms that support Node.js:

#### Vercel (Recommended)
```bash
# 1. Install Vercel CLI
npm i -g vercel

# 2. Deploy
vercel

# 3. Set environment variables in Vercel dashboard:
# JWT_SECRET=your-super-secret-jwt-key-production
# NODE_ENV=production
```

#### Railway
```bash
# 1. Install Railway CLI
npm install -g @railway/cli

# 2. Login and deploy
railway login
railway up
```

#### Render
1. Connect your GitHub repository
2. Create a new Web Service
3. Set build command: `npm run build`
4. Set start command: `npm start`
5. Add environment variables in dashboard

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
