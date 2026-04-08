import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, User, LogOut, History, AlertTriangle, CheckCircle, Settings, Fingerprint, Zap, Key, ShieldCheck, Mail, Calendar } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { cn } from '@/lib/utils';

interface PasswordHistoryItem {
  id: string;
  strength: string;
  score: number;
  entropy: number;
  isBreached: boolean;
  breachCount: number;
  createdAt: string;
}

interface UserProfile {
  id: string;
  email: string;
  role: string;
  createdAt: string;
  lastLogin: string | null;
  twoFactorEnabled: boolean;
  passwordHistory: PasswordHistoryItem[];
}

export default function Profile() {
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const { user, logout, isAuthenticated, token } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!isAuthenticated) {
      navigate('/login');
    }
  }, [isAuthenticated, navigate]);

  useEffect(() => {
    if (!token || !isAuthenticated) return;

    const fetchProfile = async () => {
      try {
        const response = await fetch('/api/auth/profile', {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });

        if (response.ok) {
          const data = await response.json();
          setProfile(data.user);
        } else {
          setError('Failed to load profile');
        }
      } catch (error) {
        console.error('Error fetching profile:', error);
        setError('Failed to load profile');
      } finally {
        setIsLoading(false);
      }
    };

    fetchProfile();
  }, [token, isAuthenticated]);

  const getStrengthColor = (strength: string) => {
    switch (strength) {
      case 'Very Strong': return 'var(--very-strong)';
      case 'Strong': return 'var(--strong)';
      case 'Good': return 'var(--good)';
      case 'Fair': return 'var(--fair)';
      case 'Weak': return 'var(--weak)';
      case 'Very Weak': return 'var(--very-weak)';
      default: return '#64748b';
    }
  };

  if (!isAuthenticated) return null;

  if (isLoading) {
    return (
      <div className="min-h-screen premium-gradient-bg flex items-center justify-center">
        <motion.div 
          animate={{ scale: [1, 1.1, 1] }}
          transition={{ duration: 1, repeat: Infinity }}
          className="text-center"
        >
          <Fingerprint className="h-12 w-12 text-primary mx-auto mb-4" />
          <p className="font-bold text-slate-500 uppercase tracking-widest text-xs">Accessing Vault...</p>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="min-h-screen premium-gradient-bg relative overflow-hidden font-sans">
      <div className="hero-glow" />
      <div className="hero-glow-alt" />

      {/* Header */}
      <motion.header 
        initial={{ y: -20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        className="sticky top-0 z-50 glass-header"
      >
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-3">
              <div className="p-2 bg-primary rounded-xl shadow-lg shadow-primary/20">
                <Shield className="h-6 w-6 text-white" />
              </div>
              <h1 className="text-2xl font-black tracking-tight text-slate-900 dark:text-white uppercase transition-all hover:scale-105">
                SECURE<span className="text-primary italic">PASS</span>
              </h1>
            </Link>
            
            <div className="flex items-center gap-4">
              <Button variant="ghost" size="sm" asChild className="rounded-full font-bold">
                <Link to="/">Analyzer</Link>
              </Button>
              {user?.role === 'admin' && (
                <Button variant="outline" size="sm" asChild className="rounded-full shadow-sm bg-white/50 dark:bg-slate-900/50">
                  <Link to="/admin">Admin Panel</Link>
                </Button>
              )}
              <Button 
                variant="ghost" 
                size="icon" 
                onClick={logout}
                className="rounded-full hover:bg-red-500/10 hover:text-red-500 transition-colors"
              >
                <LogOut className="h-5 w-5" />
              </Button>
            </div>
          </div>
        </div>
      </motion.header>

      {/* Main Content */}
      <main className="container mx-auto px-6 py-12 relative z-10">
        <div className="max-w-6xl mx-auto">
          {/* Page Header */}
          <div className="mb-12">
            <motion.div
              initial={{ x: -20, opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              className="flex items-center gap-2 mb-4"
            >
              <div className="h-1 w-8 bg-primary rounded-full" />
              <span className="text-[10px] font-black uppercase tracking-[0.2em] text-primary">Secure Vault Hub</span>
            </motion.div>
            <motion.h2 
              initial={{ y: 20, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ delay: 0.1 }}
              className="text-4xl md:text-5xl font-black text-slate-900 dark:text-white mb-4 tracking-tight"
            >
              Operator <span className="text-primary underline decoration-emerald-500 decoration-4 underline-offset-8">Information</span>
            </motion.h2>
          </div>

          {error && (
            <Alert variant="destructive" className="mb-8 glass-card border-red-500/50 bg-red-500/5">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription className="font-bold">{error}</AlertDescription>
            </Alert>
          )}

          {profile && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
              {/* Profile Info Sidebar */}
              <motion.div 
                initial={{ x: -30, opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                transition={{ delay: 0.2 }}
                className="lg:col-span-4 space-y-6"
              >
                <Card className="glass-card border-0 shadow-2xl overflow-hidden group">
                  <div className="absolute top-0 right-0 p-8 opacity-5 group-hover:scale-110 transition-transform duration-700">
                    <Fingerprint className="h-32 w-32 text-primary" />
                  </div>
                  <CardHeader className="border-b border-white/10 pb-8">
                    <CardTitle className="text-xl font-black flex items-center gap-2">
                       Account Status
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="pt-8 space-y-6">
                    <div className="space-y-1">
                      <Label className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Operator Identity</Label>
                      <p className="text-lg font-bold flex items-center gap-2">
                        <Mail className="h-4 w-4 text-primary" /> {profile.email}
                      </p>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-1">
                        <Label className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Protocol Role</Label>
                        <div>
                          <Badge variant={profile.role === 'admin' ? 'default' : 'secondary'} className="rounded-lg font-black uppercase text-[10px] tracking-widest">
                            {profile.role}
                          </Badge>
                        </div>
                      </div>
                      <div className="space-y-1">
                        <Label className="text-[10px] font-black text-slate-400 uppercase tracking-widest">2FA Matrix</Label>
                        <div>
                          <Badge variant={profile.twoFactorEnabled ? 'default' : 'outline'} className={cn(
                            "rounded-lg font-black uppercase text-[10px] tracking-widest",
                            profile.twoFactorEnabled ? "bg-emerald-500 text-white" : "border-slate-200"
                          )}>
                            {profile.twoFactorEnabled ? 'Active' : 'Offline'}
                          </Badge>
                        </div>
                      </div>
                    </div>
                    <div className="space-y-1">
                      <Label className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Initialized On</Label>
                      <p className="text-sm font-semibold flex items-center gap-2 text-slate-600">
                        <Calendar className="h-4 w-4" /> {new Date(profile.createdAt).toLocaleDateString()}
                      </p>
                    </div>
                  </CardContent>
                </Card>

                <Card className="glass-card border-0 shadow-xl overflow-hidden">
                  <CardHeader>
                    <CardTitle className="text-sm font-black uppercase tracking-widest text-primary flex items-center gap-2">
                      <Settings className="h-4 w-4" /> Security Operations
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <Button variant="outline" className="w-full h-12 rounded-xl font-bold bg-white/30 hover:bg-primary hover:text-white transition-all border-slate-200" disabled>
                      Synchronize Access Key
                    </Button>
                    <Button variant="outline" className="w-full h-12 rounded-xl font-bold bg-white/30 hover:bg-emerald-500 hover:text-white transition-all border-slate-200" disabled>
                      Enable Dual-Phase Auth
                    </Button>
                    <Button variant="ghost" className="w-full h-12 rounded-xl font-bold text-red-500 hover:bg-red-500/10" disabled>
                      Decommission Vault
                    </Button>
                  </CardContent>
                </Card>
              </motion.div>

              {/* Password History Grid */}
              <motion.div 
                initial={{ x: 30, opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                transition={{ delay: 0.3 }}
                className="lg:col-span-8"
              >
                <Card className="glass-card border-0 shadow-2xl overflow-hidden">
                  <CardHeader className="border-b border-white/10 pb-8 bg-white/20 dark:bg-slate-900/20">
                    <div className="flex items-center justify-between">
                      <div>
                        <CardTitle className="text-2xl font-black flex items-center gap-2">
                           Analysis Evolution
                        </CardTitle>
                        <CardDescription className="font-medium text-slate-500">
                          Historical security trajectory and breach exposure monitoring.
                        </CardDescription>
                      </div>
                      <div className="p-3 bg-primary/10 rounded-2xl">
                        <History className="h-6 w-6 text-primary" />
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="pt-8">
                    {profile.passwordHistory.length > 0 ? (
                      <div className="grid grid-cols-1 gap-6">
                        <AnimatePresence>
                          {profile.passwordHistory.map((item, index) => (
                            <motion.div 
                              key={item.id}
                              initial={{ y: 20, opacity: 0 }}
                              animate={{ y: 0, opacity: 1 }}
                              transition={{ delay: 0.1 * index }}
                              className="group relative"
                            >
                              <div className="absolute -inset-0.5 bg-gradient-to-r from-primary/10 to-emerald-500/10 rounded-2xl blur opacity-0 group-hover:opacity-100 transition duration-500" />
                              <div className="relative p-6 rounded-2xl bg-white/50 dark:bg-slate-900/50 border border-slate-100 dark:border-slate-800 shadow-sm hover:shadow-md transition-all">
                                <div className="flex items-center justify-between mb-4">
                                  <div className="flex items-center gap-3">
                                    <div className="h-2 w-2 rounded-full animate-pulse" style={{ backgroundColor: getStrengthColor(item.strength) }} />
                                    <h4 className="text-lg font-black tracking-tight" style={{ color: getStrengthColor(item.strength) }}>
                                      {item.strength.toUpperCase()}
                                    </h4>
                                    {item.isBreached && (
                                      <Badge variant="destructive" className="rounded-lg font-black text-[8px] uppercase tracking-widest px-2">
                                        Compromised
                                      </Badge>
                                    )}
                                  </div>
                                  <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">
                                    TS: {new Date(item.createdAt).toLocaleDateString()}
                                  </span>
                                </div>
                                
                                <div className="grid grid-cols-3 gap-6">
                                  <div className="space-y-1">
                                    <p className="text-[9px] font-black text-slate-400 uppercase tracking-widest">Resilience</p>
                                    <p className="text-xl font-black">{item.score}%</p>
                                  </div>
                                  <div className="space-y-1">
                                    <p className="text-[9px] font-black text-slate-400 uppercase tracking-widest">Entropy</p>
                                    <p className="text-xl font-black">{item.entropy}<span className="text-[10px] text-slate-400 ml-1">bits</span></p>
                                  </div>
                                  <div className="space-y-1">
                                    <p className="text-[9px] font-black text-slate-400 uppercase tracking-widest">Leak Count</p>
                                    <p className={cn(
                                      "text-xl font-black",
                                      item.isBreached ? "text-red-500" : "text-emerald-500"
                                    )}>
                                      {item.isBreached ? item.breachCount.toLocaleString() : 'CLEAR'}
                                    </p>
                                  </div>
                                </div>

                                {item.isBreached && (
                                  <div className="mt-4 pt-4 border-t border-red-500/10">
                                    <div className="flex items-center gap-2 text-red-500">
                                      <AlertTriangle className="h-4 w-4" />
                                      <p className="text-xs font-bold">Identified in {item.breachCount.toLocaleString()} major data leaks.</p>
                                    </div>
                                  </div>
                                )}
                              </div>
                            </motion.div>
                          ))}
                        </AnimatePresence>
                      </div>
                    ) : (
                      <div className="text-center py-20 px-6">
                        <div className="w-20 h-20 rounded-full bg-slate-50 dark:bg-slate-800 inline-flex items-center justify-center mb-6">
                          <History className="h-10 w-10 text-slate-300" />
                        </div>
                        <h3 className="text-2xl font-black mb-3">No History Records</h3>
                        <p className="text-slate-500 font-medium max-w-sm mx-auto mb-8">
                          Your vault history is currently empty. Run your first analysis to start tracking your security metrics.
                        </p>
                        <Button asChild className="h-14 px-8 rounded-2xl shadow-xl shadow-primary/20 font-black uppercase tracking-widest">
                          <Link to="/">Initialize Analysis</Link>
                        </Button>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </motion.div>
            </div>
          )}
        </div>
      </main>

      <footer className="container mx-auto px-6 py-12 text-center text-slate-400 font-extrabold text-[8px] uppercase tracking-[0.3em] opacity-40 border-t border-white/10 mt-20 relative z-10">
        Operator Session BB-6C43-B7 // Encrypted Cache Active
      </footer>
    </div>
  );
}

