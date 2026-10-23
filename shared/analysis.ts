import { PasswordAnalysisResponse } from './api';

// Common passwords list for local heuristics
export const COMMON_PASSWORDS = new Set([
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
export const KEYBOARD_PATTERNS = [
  'qwerty', 'asdfgh', 'zxcvbn', 'qwertz', 'azerty',
  '12345', '23456', '34567', '45678', '56789', '67890',
  '09876', '98765', '87654', '76543', '65432', '54321',
  'poiuy', 'lkjhg', 'mnbvc'
];

export function normalizeLeetspeak(str: string): string {
  return str
    .toLowerCase()
    .replace(/[@4]/g, 'a')
    .replace(/[3]/g, 'e')
    .replace(/[1!|]/g, 'i')
    .replace(/[0]/g, 'o')
    .replace(/[5$]/g, 's')
    .replace(/[7+]/g, 't');
}

export function calculateEntropy(password: string): number {
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

export function calculateCrackTime(entropy: number): { seconds: number; display: string; scenario: string } {
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

export function analyzePasswordLocally(password: string): PasswordAnalysisResponse {
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
      breachStatus: 'clean',
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
