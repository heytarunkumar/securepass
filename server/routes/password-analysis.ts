import { RequestHandler } from "express";
import { PasswordAnalysisRequest, PasswordAnalysisResponse } from "@shared/api";
import { passwordCheckDb, passwordHistoryDb } from "../database";
import { AuthRequest } from "../auth";
import crypto from 'crypto';

// Common passwords to check against
const COMMON_PASSWORDS = [
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
  'ashley', 'thomas', 'helicopter', 'joshua', 'mustang', 'thunder'
];

function calculateEntropy(password: string): number {
  let charSpace = 0;
  const hasLowercase = /[a-z]/.test(password);
  const hasUppercase = /[A-Z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChars = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  if (hasLowercase) charSpace += 26;
  if (hasUppercase) charSpace += 26;
  if (hasNumbers) charSpace += 10;
  if (hasSpecialChars) charSpace += 32;

  return password.length * Math.log2(charSpace || 1);
}

function calculateCrackTime(entropy: number): { seconds: number; display: string } {
  // Assume 1 billion guesses per second (modern GPU)
  const guessesPerSecond = 1e9;
  const totalCombinations = Math.pow(2, entropy);
  const averageGuesses = totalCombinations / 2;
  const seconds = averageGuesses / guessesPerSecond;

  if (seconds < 1) return { seconds, display: 'Instantly' };
  if (seconds < 60) return { seconds, display: `${Math.round(seconds)} seconds` };
  if (seconds < 3600) return { seconds, display: `${Math.round(seconds / 60)} minutes` };
  if (seconds < 86400) return { seconds, display: `${Math.round(seconds / 3600)} hours` };
  if (seconds < 2629746) return { seconds, display: `${Math.round(seconds / 86400)} days` };
  if (seconds < 31556952) return { seconds, display: `${Math.round(seconds / 2629746)} months` };
  if (seconds < 315569520) return { seconds, display: `${Math.round(seconds / 31556952)} years` };
  if (seconds < 3155695200) return { seconds, display: `${Math.round(seconds / 315569520)} decades` };
  return { seconds, display: 'Centuries' };
}

function analyzePassword(password: string): PasswordAnalysisResponse {
  if (!password) {
    return {
      score: 0,
      strength: 'Very Weak',
      color: '#ef4444',
      suggestions: ['Enter a password to get started'],
      entropy: 0,
      crackTime: 'Instantly',
      timeToCrack: { seconds: 0, display: 'Instantly' },
      checks: {
        hasLength: false,
        hasUppercase: false,
        hasLowercase: false,
        hasNumbers: false,
        hasSpecialChars: false,
        isCommon: false
      }
    };
  }

  const checks = {
    hasLength: password.length >= 8,
    hasUppercase: /[A-Z]/.test(password),
    hasLowercase: /[a-z]/.test(password),
    hasNumbers: /\d/.test(password),
    hasSpecialChars: /[!@#$%^&*(),.?":{}|<>]/.test(password),
    isCommon: COMMON_PASSWORDS.includes(password.toLowerCase())
  };

  const entropy = calculateEntropy(password);
  const timeToCrack = calculateCrackTime(entropy);

  // Calculate score based on multiple factors
  let score = 0;
  
  // Length scoring
  if (checks.hasLength) score += 20;
  if (password.length >= 12) score += 10;
  if (password.length >= 16) score += 10;
  if (password.length >= 20) score += 5;

  // Character type scoring
  if (checks.hasUppercase) score += 15;
  if (checks.hasLowercase) score += 15;
  if (checks.hasNumbers) score += 15;
  if (checks.hasSpecialChars) score += 20;

  // Penalties
  if (checks.isCommon) score -= 40;

  // Entropy bonus
  if (entropy > 40) score += 5;
  if (entropy > 60) score += 10;
  if (entropy > 80) score += 10;

  // Pattern detection penalties
  if (/(.)\1{2,}/.test(password)) score -= 10; // Repeated characters
  if (/012|123|234|345|456|567|678|789|890/.test(password)) score -= 10; // Sequential numbers
  if (/abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/i.test(password)) score -= 10; // Sequential letters

  score = Math.max(0, Math.min(100, score));

  // Generate suggestions
  const suggestions: string[] = [];
  if (!checks.hasLength) suggestions.push('Use at least 8 characters');
  if (!checks.hasUppercase) suggestions.push('Add uppercase letters (A-Z)');
  if (!checks.hasLowercase) suggestions.push('Add lowercase letters (a-z)');
  if (!checks.hasNumbers) suggestions.push('Include numbers (0-9)');
  if (!checks.hasSpecialChars) suggestions.push('Add special characters (!@#$%^&*)');
  if (password.length < 12) suggestions.push('Consider using 12+ characters for better security');
  if (checks.isCommon) suggestions.push('Avoid common passwords');
  if (/(.)\1{2,}/.test(password)) suggestions.push('Avoid repeating characters');
  if (/012|123|234|345|456|567|678|789|890/.test(password)) suggestions.push('Avoid sequential numbers');

  if (suggestions.length === 0) {
    suggestions.push('Excellent! Your password meets all security criteria');
  }

  // Determine strength and color
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
    entropy: Math.round(entropy * 10) / 10,
    crackTime: timeToCrack.display,
    timeToCrack,
    checks
  };
}

// Simple in-memory cache for breach checking (in production, use Redis)
const breachCache = new Map<string, { isBreached: boolean; count: number; timestamp: number }>();

async function checkPasswordBreach(password: string): Promise<{ isBreached: boolean; count: number }> {
  try {
    // Check cache first (cache for 1 hour)
    const cached = breachCache.get(password);
    if (cached && Date.now() - cached.timestamp < 3600000) {
      return { isBreached: cached.isBreached, count: cached.count };
    }

    // Hash the password using SHA-1
    const crypto = require('crypto');
    const sha1Hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = sha1Hash.substring(0, 5);
    const suffix = sha1Hash.substring(5);

    // Query Have I Been Pwned API
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    if (!response.ok) {
      throw new Error('Failed to check breach database');
    }

    const data = await response.text();
    const lines = data.split('\n');
    
    for (const line of lines) {
      const [hashSuffix, count] = line.split(':');
      if (hashSuffix === suffix) {
        const result = { isBreached: true, count: parseInt(count.trim()) };
        breachCache.set(password, { ...result, timestamp: Date.now() });
        return result;
      }
    }

    const result = { isBreached: false, count: 0 };
    breachCache.set(password, { ...result, timestamp: Date.now() });
    return result;
  } catch (error) {
    console.error('Error checking password breach:', error);
    return { isBreached: false, count: 0 };
  }
}

export const handlePasswordAnalysis: RequestHandler = async (req: AuthRequest, res) => {
  try {
    const { password, saveToHistory } = req.body as PasswordAnalysisRequest & { saveToHistory?: boolean };

    if (typeof password !== 'string') {
      return res.status(400).json({ error: 'Password must be a string' });
    }

    // Analyze password strength
    const analysis = analyzePassword(password);

    // Check for breaches (only if password is not empty)
    if (password.length > 0) {
      const breachInfo = await checkPasswordBreach(password);
      analysis.isBreached = breachInfo.isBreached;
      analysis.breachCount = breachInfo.count;

      if (breachInfo.isBreached) {
        analysis.suggestions.unshift(`⚠️ This password has been found in ${breachInfo.count.toLocaleString()} data breaches. Choose a different password.`);
        analysis.score = Math.min(analysis.score, 30); // Cap score at 30 for breached passwords
        analysis.strength = analysis.score >= 25 ? 'Weak' : 'Very Weak';
        analysis.color = analysis.score >= 25 ? '#f97316' : '#ef4444';
      }
    }

    // Log the password check (hash the password for privacy)
    const passwordHash = password ? crypto.createHash('sha256').update(password).digest('hex') : '';
    passwordCheckDb.log(
      req.user?.id || null,
      passwordHash,
      analysis,
      req.ip,
      req.get('User-Agent')
    );

    // Save to user's password history if requested and user is authenticated
    if (saveToHistory && req.user && password.length > 0) {
      passwordHistoryDb.add(req.user.id, passwordHash, analysis);
    }

    res.json(analysis);
  } catch (error) {
    console.error('Password analysis error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};
