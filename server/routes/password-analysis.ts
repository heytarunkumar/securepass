import { RequestHandler } from 'express';
import crypto from 'node:crypto';
import { PasswordAnalysisResponse, BreachStatus } from '../../shared/api';
import { analyzePasswordLocally } from '../../shared/analysis';
import { passwordCheckDb, passwordHistoryDb } from '../database';
import { AuthRequest } from '../auth';
import { PasswordAnalysisSchema } from '../validation';


// SP-02 & SP-08: Bounded LRU/TTL Cache of anonymous 5-character HIBP range prefixes
// NEVER stores plain passwords or password hashes as cache keys!
interface CachedRange {
  suffixes: Map<string, number>;
  timestamp: number;
}

const MAX_PREFIX_CACHE_SIZE = 500;
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const prefixRangeCache = new Map<string, CachedRange>();

function getCachedRange(prefix: string): Map<string, number> | null {
  const cached = prefixRangeCache.get(prefix);
  if (!cached) return null;
  if (Date.now() - cached.timestamp > CACHE_TTL_MS) {
    prefixRangeCache.delete(prefix);
    return null;
  }
  return cached.suffixes;
}

function setCachedRange(prefix: string, suffixes: Map<string, number>) {
  // Evict oldest entry if capacity reached
  if (prefixRangeCache.size >= MAX_PREFIX_CACHE_SIZE) {
    const firstKey = prefixRangeCache.keys().next().value;
    if (firstKey) prefixRangeCache.delete(firstKey);
  }
  prefixRangeCache.set(prefix, { suffixes, timestamp: Date.now() });
}

export interface BreachCheckResult {
  status: BreachStatus;
  isBreached: boolean;
  count: number;
}

// SP-04: Tri-state breach check with strict timeout and no false-negative clean reports
async function checkPasswordBreach(password: string): Promise<BreachCheckResult> {
  if (!password) {
    return { status: 'clean', isBreached: false, count: 0 };
  }

  // Calculate SHA-1 transiently in local scope only
  const sha1Hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
  const prefix = sha1Hash.substring(0, 5);
  const suffix = sha1Hash.substring(5);

  let suffixes = getCachedRange(prefix);

  if (!suffixes) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3500);

      const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        signal: controller.signal,
        headers: {
          'Add-Padding': 'true', // K-anonymity padding to prevent response size leakage
          'User-Agent': 'SecurePass-Audited/1.0',
        },
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        // Upstream service returned an error status: mark as unavailable (do NOT claim clean)
        return { status: 'unavailable', isBreached: false, count: 0 };
      }

      const text = await response.text();
      suffixes = new Map<string, number>();

      const lines = text.split('\r\n').join('\n').split('\n');
      for (const line of lines) {
        const parts = line.split(':');
        if (parts.length === 2) {
          const s = parts[0].trim().toUpperCase();
          const c = parseInt(parts[1].trim(), 10);
          if (s && !isNaN(c)) {
            suffixes.set(s, c);
          }
        }
      }

      setCachedRange(prefix, suffixes);
    } catch (error) {
      // Network failure, timeout, or abort: return unavailable (SP-04)
      return { status: 'unavailable', isBreached: false, count: 0 };
    }
  }

  const breachCount = suffixes.get(suffix);
  if (breachCount && breachCount > 0) {
    return { status: 'breached', isBreached: true, count: breachCount };
  }

  return { status: 'clean', isBreached: false, count: 0 };
}

// SP-08: In-memory rate limiting for password analysis endpoint (60 requests/minute per IP)
const analysisRateLimitMap = new Map<string, { count: number; resetAt: number }>();
function checkAnalysisRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = analysisRateLimitMap.get(ip);
  if (!entry || now > entry.resetAt) {
    analysisRateLimitMap.set(ip, { count: 1, resetAt: now + 60000 });
    return true;
  }
  if (entry.count >= 60) {
    return false;
  }
  entry.count++;
  return true;
}

export const handlePasswordAnalysis: RequestHandler = async (req: AuthRequest, res) => {
  try {
    const clientIp = req.ip || 'anonymous';
    if (!checkAnalysisRateLimit(clientIp)) {
      return res.status(429).json({ error: 'Too many analysis requests. Please slow down.' });
    }

    const parseResult = PasswordAnalysisSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({ error: parseResult.error.errors[0]?.message || 'Invalid input' });
    }

    const { password, saveToHistory } = parseResult.data;

    // Analyze password strength locally
    const analysis = analyzePasswordLocally(password);

    // SP-04: Breach checking with tri-state status
    if (password.length > 0) {
      const breachInfo = await checkPasswordBreach(password);
      analysis.breachStatus = breachInfo.status;
      analysis.isBreached = breachInfo.isBreached;
      analysis.breachCount = breachInfo.count;

      if (breachInfo.status === 'breached') {
        analysis.suggestions.unshift(`⚠️ CRITICAL LEAK: This password was found in ${breachInfo.count.toLocaleString()} data breaches. Choose a different password immediately.`);
        analysis.score = Math.min(analysis.score, 25);
        analysis.strength = analysis.score >= 20 ? 'Weak' : 'Very Weak';
        analysis.color = '#ef4444';
      } else if (breachInfo.status === 'unavailable') {
        analysis.suggestions.unshift('ℹ️ Breach-check service is temporarily unreachable. Strength evaluated by offline criteria only.');
      }
    }

    // SP-02: Log metadata only. NEVER store raw passwords or unsalted SHA-256 hashes!
    try {
      passwordCheckDb.log(
        req.user?.id || null,
        analysis,
        req.ip,
        req.get('User-Agent')
      );

      // Save to user's password history if requested and user is authenticated
      if (saveToHistory && req.user && password.length > 0) {
        passwordHistoryDb.add(req.user.id, analysis);
      }
    } catch (logErr) {
      console.error('Non-critical: Failed to log password check metrics:', logErr);
    }

    res.json(analysis);
  } catch (error) {
    console.error('Password analysis error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};
