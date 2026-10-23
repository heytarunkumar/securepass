import { z } from 'zod';

// Modern password validation policy (emphasizing length, entropy, and bounds)
export const passwordPolicyRegex = {
  uppercase: /[A-Z]/,
  lowercase: /[a-z]/,
  number: /\d/,
  specialChar: /[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/]/,
};

export const RegistrationSchema = z.object({
  email: z
    .string({ required_error: 'Email is required' })
    .trim()
    .toLowerCase()
    .email('Please enter a valid email address')
    .max(255, 'Email cannot exceed 255 characters'),
  password: z
    .string({ required_error: 'Password is required' })
    .min(8, 'Password must be at least 8 characters long')
    .max(72, 'Password cannot exceed 72 characters (bcrypt hashing limit)')
    .refine((val) => passwordPolicyRegex.uppercase.test(val), {
      message: 'Password must contain at least one uppercase letter',
    })
    .refine((val) => passwordPolicyRegex.lowercase.test(val), {
      message: 'Password must contain at least one lowercase letter',
    })
    .refine((val) => passwordPolicyRegex.number.test(val), {
      message: 'Password must contain at least one number',
    })
    .refine((val) => passwordPolicyRegex.specialChar.test(val), {
      message: 'Password must contain at least one special character',
    }),
  confirmPassword: z.string({ required_error: 'Password confirmation is required' }),
}).refine((data) => data.password === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword'],
});

export const LoginSchema = z.object({
  email: z
    .string({ required_error: 'Email is required' })
    .trim()
    .toLowerCase()
    .email('Please enter a valid email address')
    .max(255, 'Email cannot exceed 255 characters'),
  password: z
    .string({ required_error: 'Password is required' })
    .min(1, 'Password is required')
    .max(72, 'Password cannot exceed 72 characters'),
});

export const PasswordAnalysisSchema = z.object({
  password: z
    .string({ required_error: 'Password must be a string' })
    .max(256, 'Password exceeds maximum analysis length of 256 characters'),
  saveToHistory: z.boolean().optional(),
});
