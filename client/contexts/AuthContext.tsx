import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { AuthResponse } from '@shared/api';

interface User {
  id: string;
  email: string;
  role: 'user' | 'admin';
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  login: (email: string, password: string) => Promise<{ success: boolean; message: string }>;
  register: (email: string, password: string, confirmPassword: string) => Promise<{ success: boolean; message: string }>;
  logout: () => void;
  isLoading: boolean;
  isAuthenticated: boolean;
  isAdmin: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Initialize auth state from localStorage
  useEffect(() => {
    const savedToken = localStorage.getItem('auth_token');
    const savedUser = localStorage.getItem('auth_user');

    if (savedToken && savedUser) {
      try {
        setToken(savedToken);
        setUser(JSON.parse(savedUser));
      } catch (error) {
        console.error('Error parsing saved user data:', error);
        localStorage.removeItem('auth_token');
        localStorage.removeItem('auth_user');
      }
    }
    setIsLoading(false);
  }, []);

  const login = async (email: string, password: string): Promise<{ success: boolean; message: string }> => {
    try {
      setIsLoading(true);
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });

      let data: any = null;
      try {
        data = await response.json();
      } catch {
        const text = await response.text().catch(() => '');
        return {
          success: false,
          message: text || `Authentication failed (Server status: ${response.status})`,
        };
      }

      if (data && (data.success || response.ok) && data.token && data.user) {
        setToken(data.token);
        setUser(data.user);
        localStorage.setItem('auth_token', data.token);
        localStorage.setItem('auth_user', JSON.stringify(data.user));
        return { success: true, message: data.message || 'Login successful' };
      } else {
        return { success: false, message: data?.message || data?.error || 'Invalid credentials' };
      }
    } catch (error: any) {
      console.error('Login error:', error);
      return { success: false, message: error?.message || 'Network error. Please try again.' };
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (email: string, password: string, confirmPassword: string): Promise<{ success: boolean; message: string }> => {
    try {
      setIsLoading(true);
      const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password, confirmPassword }),
      });

      let data: any = null;
      try {
        data = await response.json();
      } catch {
        const text = await response.text().catch(() => '');
        return {
          success: false,
          message: text || `Registration failed (Server status: ${response.status})`,
        };
      }

      if (data && (data.success || response.ok) && data.token && data.user) {
        setToken(data.token);
        setUser(data.user);
        localStorage.setItem('auth_token', data.token);
        localStorage.setItem('auth_user', JSON.stringify(data.user));
        return { success: true, message: data.message || 'Account created successfully' };
      } else {
        return { success: false, message: data?.message || data?.error || 'Registration failed' };
      }
    } catch (error: any) {
      console.error('Registration error:', error);
      return { success: false, message: error?.message || 'Network error. Please try again.' };
    } finally {
      setIsLoading(false);
    }
  };


  const logout = () => {
    const currentToken = token;
    setUser(null);
    setToken(null);
    localStorage.removeItem('auth_token');
    localStorage.removeItem('auth_user');
    
    // Call server-side logout endpoint to revoke session immediately (SP-05)
    if (currentToken) {
      fetch('/api/auth/logout', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${currentToken}`,
        },
      }).catch(console.error);
    }
  };

  const value: AuthContextType = {
    user,
    token,
    login,
    register,
    logout,
    isLoading,
    isAuthenticated: !!user,
    isAdmin: user?.role === 'admin',
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// Helper function to get auth headers
export const getAuthHeaders = (token: string | null) => {
  return token ? { 'Authorization': `Bearer ${token}` } : {};
};
