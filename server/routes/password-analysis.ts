import { RequestHandler } from 'express';
import crypto from 'node:crypto';
import { PasswordAnalysisResponse, BreachStatus } from '@shared/api';
import { passwordCheckDb, passwordHistoryDb } from '../database';
import { AuthRequest } from '../auth';
import { PasswordAnalysisSchema } from '../validation';

// Common passwords list for local heuristics
const COMMON_PASSWORDS = new Set([
  'password', '123456', '123456789', 'qwerty', 'abc123', 'password123',
  'admin', 'letmein', 'welcome', 'monkey', '1234567890', 'dragon',
  'pass', 'master', 'hello', 'freedom', 'whatever', 'qazwsx',
  'trustno1', 'jordan', 'harley', 'robert', 'matthew', 'jordan23',
  'password1', '000000', 'superman', 'jennifer', 'joshua', 'hunter',
  'baseball', 'michael', 'tigger', 'michelle', 'jordan', 'mustang',
  'liverpool', 'football', 'access', 'buster', 'soccer', 'hockey',
  'killer', 'george', 'computer', 'michelle', 'jessica', 'pepper',
  'prince', 'shadow', 'cheese', 'dakota', 'sunshine', 'iloveyou',
  'princess', 'hannah', 'red123', 'alexander', 'slayer', 'qwerty123',
  'ashley', 'thomas', 'helicopter', 'joshua', 'mustang', 'thunder',
  'securepass', 'admin123', 'changeme', 'iloveyou1', 'secret'
]);

// Common keyboard patterns
const KEYBOARD_PATTERNS = [
  'qwerty', 'asdfgh', 'zxcvbn', 'qwertz', 'azerty',
  '12345', '23456', '34567', '45678', '56789', '67890',
  '09876', '98765', '87654', '76543', '65432', '54321',
  'poiuy', 'lkjhg', 'mnbvc'
];

function normalizeLeetspeak(str: string): string {
  return str
    .toLowerCase()
    .replace(/[@4]/g, 'a')
    .replace(/[3]/g, 'e')
    .replace(/[1!|]/g, 'i')
    .replace(/[0]/g, 'o')
    .replace(/[5$]/g, 's')
    .replace(/[7+]/g, 't');
}

function calculateEntropy(password: string): number {
  if (!password) return 0;
  let charSpace = 0;
  const hasLowercase = /[a-z]/.test(password);
  const hasUppercase = /[A-Z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChars = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  if (hasLowercase) charSpace += 26;
  if (hasUppercase) charSpace += 26;
  if (hasNumbers) charSpace += 10;
  if (hasSpecialChars) charSpace += 32;

  return Math.round(password.length * Math.log2(charSpace || 1) * 10) / 10;
}

function calculateCrackTime(entropy: number): { seconds: number; display: string; scenario: string } {
  const guessesPerSecond = 1e9; // 1 billion guesses/sec (fast GPU cluster)
  const totalCombinations = Math.pow(2, entropy);
  const averageGuesses = totalCombinations / 2;
  const seconds = averageGuesses / guessesPerSecond;

  const scenario = 'Offline brute-force estimate assuming 10^9 guesses/sec GPU cluster. Online attempts are throttled.';

  if (seconds < 1) return { seconds, display: 'Instantly', scenario };
  if (seconds < 60) return { seconds, display: `${Math.round(seconds)} seconds`, scenario };
  if (seconds < 3600) return { seconds, display: `${Math.round(seconds / 60)} minutes`, scenario };
  if (seconds < 86400) return { seconds, display: `${Math.round(seconds / 3600)} hours`, scenario };
  if (seconds < 2629746) return { seconds, display: `${Math.round(seconds / 86400)} days`, scenario };
  if (seconds < 31556952) return { seconds, display: `${Math.round(seconds / 2629746)} months`, scenario };
  if (seconds < 315569520) return { seconds, display: `${Math.round(seconds / 31556952)} years`, scenario };
  if (seconds < 3155695200) return { seconds, display: `${Math.round(seconds / 315569520)} decades`, scenario };
  return { seconds, display: 'Centuries', scenario };
}

function analyzePassword(password: string): PasswordAnalysisResponse {
  if (!password) {
    return {
      score: 0,
      strength: 'Very Weak',
      color: '#ef4444',
      suggestions: ['Enter a password to begin analysis'],
      entropy: 0,
      crackTime: 'Instantly',
      timeToCrack: { seconds: 0, display: 'Instantly' },
      checks: {
        hasLength: false,
        hasUppercase: false,
        hasLowercase: false,
        hasNumbers: false,
        hasSpecialChars: false,
        isCommon: false,
      },
    };
  }

  const normalized = password.toLowerCase();
  const deLeet = normalizeLeetspeak(password);

  const isCommon = COMMON_PASSWORDS.has(normalized) || COMMON_PASSWORDS.has(deLeet);
  const hasKeyboardPattern = KEYBOARD_PATTERNS.some((pat) => normalized.includes(pat));

  const checks = {
    hasLength: password.length >= 8,
    hasUppercase: /[A-Z]/.test(password),
    hasLowercase: /[a-z]/.test(password),
    hasNumbers: /\d/.test(password),
    hasSpecialChars: /[!@#$%^&*(),.?":{}|<>]/.test(password),
    isCommon: isCommon || hasKeyboardPattern,
  };

  const entropy = calculateEntropy(password);
  const timeToCrack = calculateCrackTime(entropy);

  let score = 0;

  // Length scoring
  if (checks.hasLength) score += 20;
  if (password.length >= 12) score += 15;
  if (password.length >= 16) score += 10;
  if (password.length >= 20) score += 10;

  // Character variety
  if (checks.hasUppercase) score += 10;
  if (checks.hasLowercase) score += 10;
  if (checks.hasNumbers) score += 10;
  if (checks.hasSpecialChars) score += 15;

  // Penalties
  if (isCommon) score -= 45;
  if (hasKeyboardPattern) score -= 25;
  if (/(.)\1{2,}/.test(password)) score -= 15; // Repeating characters
  if (/012|123|234|345|456|567|678|789|890/.test(password)) score -= 10;
  if (/abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|nop|opq|pqr|qrs|rst|stu|vwx|xyz/i.test(password)) score -= 10;

  // Entropy adjustments
  if (entropy > 50) score += 5;
  if (entropy > 70) score += 10;

  score = Math.max(0, Math.min(100, score));

  const suggestions: string[] = [];
  if (!checks.hasLength) suggestions.push('Use at least 8 characters (14+ recommended)');
  if (!checks.hasUppercase) suggestions.push('Add uppercase letters (A-Z)');
  if (!checks.hasLowercase) suggestions.push('Add lowercase letters (a-z)');
  if (!checks.hasNumbers) suggestions.push('Include numbers (0-9)');
  if (!checks.hasSpecialChars) suggestions.push('Add special characters (!@#$%^&*)');
  if (password.length < 14) suggestions.push('Longer passphrases provide exponential resilience against GPU attacks');
  if (isCommon) suggestions.push('Avoid easily guessable or dictionary words');
  if (hasKeyboardPattern) suggestions.push('Avoid keyboard walks (e.g., qwerty, 12345)');
  if (/(.)\1{2,}/.test(password)) suggestions.push('Avoid repeating identical characters');

  if (suggestions.length === 0) {
    suggestions.push('Strong password structure with high theoretical entropy');
  }

  let strength: PasswordAnalysisResponse['strength'];
  let color: string;

  if (score >= 90) {
    strength = 'Very Strong';
    color = '#10b981';
  } else if (score >= 75) {
    strength = 'Strong';
    color = '#22c55e';
  } else if (score >= 60) {
    strength = 'Good';
    color = '#3b82f6';
  } else if (score >= 40) {
    strength = 'Fair';
    color = '#eab308';
  } else if (score >= 20) {
    strength = 'Weak';
    color = '#f97316';
  } else {
    strength = 'Very Weak';
    color = '#ef4444';
  }

  return {
    score,
    strength,
    color,
    suggestions,
    entropy,
    crackTime: timeToCrack.display,
    timeToCrack,
    checks,
  };
}

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
    const analysis = analyzePassword(password);

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
