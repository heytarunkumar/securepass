export interface DemoResponse {
  message: string;
}

export interface PasswordAnalysisRequest {
  password: string;
}

export interface PasswordAnalysisResponse {
  score: number;
  strength: 'Very Weak' | 'Weak' | 'Fair' | 'Good' | 'Strong' | 'Very Strong';
  color: string;
  suggestions: string[];
  entropy: number;
  crackTime: string;
  timeToCrack: {
    seconds: number;
    display: string;
  };
  checks: {
    hasLength: boolean;
    hasUppercase: boolean;
    hasLowercase: boolean;
    hasNumbers: boolean;
    hasSpecialChars: boolean;
    isCommon: boolean;
  };
  isBreached?: boolean;
  breachCount?: number;
}

export interface UserRegistrationRequest {
  email: string;
  password: string;
  confirmPassword: string;
}

export interface UserLoginRequest {
  email: string;
  password: string;
}

export interface AuthResponse {
  success: boolean;
  message: string;
  token?: string;
  user?: {
    id: string;
    email: string;
    role: 'user' | 'admin';
  };
}

export interface PasswordHistoryItem {
  id: string;
  password: string; // This would be hashed in real implementation
  strength: string;
  score: number;
  createdAt: string;
  isBreached: boolean;
}

export interface UserProfile {
  id: string;
  email: string;
  createdAt: string;
  lastLogin: string;
  passwordHistory: PasswordHistoryItem[];
  twoFactorEnabled: boolean;
}

export interface AdminStats {
  totalUsers: number;
  totalPasswordsChecked: number;
  breachedPasswordsFound: number;
  averagePasswordStrength: number;
  strengthDistribution: {
    'Very Weak': number;
    'Weak': number;
    'Fair': number;
    'Good': number;
    'Strong': number;
    'Very Strong': number;
  };
}
