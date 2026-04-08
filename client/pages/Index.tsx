import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Eye, EyeOff, Shield, AlertTriangle, CheckCircle, AlertCircle, Copy, RefreshCw, Loader2, LogOut, User, Sparkles, Zap, Fingerprint } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { cn } from '@/lib/utils';
import { PasswordAnalysisResponse } from '@shared/api';

export default function Index() {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [analysis, setAnalysis] = useState<PasswordAnalysisResponse | null>(null);
  const [isChecking, setIsChecking] = useState(false);
  const { user, logout, isAuthenticated, isAdmin, token } = useAuth();

  const analyzePassword = async (pwd: string) => {
    if (!pwd) {
      setAnalysis({
        score: 0,
        strength: 'Very Weak',
        color: '#ff4d4d',
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
          isCommon: false
        }
      });
      return;
    }

    try {
      setIsChecking(true);
      const headers: any = {
        'Content-Type': 'application/json',
      };

      if (token) {
        headers.Authorization = `Bearer ${token}`;
      }

      const response = await fetch('/api/password-analysis', {
        method: 'POST',
        headers,
        body: JSON.stringify({ password: pwd, saveToHistory: isAuthenticated }),
      });

      if (!response.ok) {
        throw new Error('Failed to analyze password');
      }

      const result: PasswordAnalysisResponse = await response.json();
      setAnalysis(result);
    } catch (error) {
      console.error('Error analyzing password:', error);
    } finally {
      setIsChecking(false);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      analyzePassword(password);
    }, 400);

    return () => clearTimeout(timer);
  }, [password]);

  const generatePassword = () => {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let result = '';
    const length = 16;
    for (let i = 0; i < length; i++) {
      result += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    setPassword(result);
  };

  const copyPassword = () => {
    navigator.clipboard.writeText(password);
  };

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
            <div className="flex items-center gap-3">
              <div className="p-2 bg-primary rounded-xl shadow-lg shadow-primary/20">
                <Shield className="h-6 w-6 text-white" />
              </div>
              <h1 className="text-2xl font-black tracking-tight text-slate-900 dark:text-white">
                SECURE<span className="text-primary italic">PASS</span>
              </h1>
            </div>
            
            <nav className="hidden md:flex items-center gap-8 mr-8">
              <a href="#" className="text-sm font-semibold hover:text-primary transition-colors">Safety Guide</a>
              <a href="#" className="text-sm font-semibold hover:text-primary transition-colors">API Docs</a>
              <a href="#" className="text-sm font-semibold hover:text-primary transition-colors">About</a>
            </nav>

            <div className="flex items-center gap-3">
              {isAuthenticated ? (
                <div className="flex items-center gap-3">
                  <Button variant="ghost" size="sm" asChild className="rounded-full">
                    <Link to="/profile" className="flex items-center gap-2">
                      <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center">
                        <User className="h-4 w-4 text-primary" />
                      </div>
                      <span className="text-xs font-bold hidden sm:inline">{user?.email}</span>
                    </Link>
                  </Button>
                  {isAdmin && (
                    <Button variant="outline" size="sm" asChild className="rounded-full shadow-sm">
                      <Link to="/admin">Admin</Link>
                    </Button>
                  )}
                  <Button variant="ghost" size="icon" onClick={logout} className="rounded-full">
                    <LogOut className="h-5 w-5" />
                  </Button>
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <Button variant="ghost" asChild className="rounded-full px-6">
                    <Link to="/login">Sign In</Link>
                  </Button>
                  <Button asChild className="rounded-full px-6 shadow-lg shadow-primary/25">
                    <Link to="/register">Get Started</Link>
                  </Button>
                </div>
              )}
            </div>
          </div>
        </div>
      </motion.header>

      {/* Main Content */}
      <main className="container mx-auto px-6 py-16 relative z-10">
        <div className="max-w-5xl mx-auto">
          {/* Hero Section */}
          <div className="text-center mb-20">
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ delay: 0.1 }}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 text-xs font-bold mb-6 border border-emerald-500/20"
            >
              <Sparkles className="h-3 w-3" />
              NEW: QUANTUM LEAK PROTECTION ACTIVE
            </motion.div>
            <motion.h2 
              initial={{ y: 20, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ delay: 0.2 }}
              className="text-5xl md:text-7xl font-black text-slate-900 dark:text-white mb-6 leading-tight"
            >
              The Science of <br/>
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-primary to-emerald-500">Uncrackable</span> Vaults
            </motion.h2>
            <motion.p 
              initial={{ y: 20, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ delay: 0.3 }}
              className="text-lg text-slate-500 dark:text-slate-400 max-w-2xl mx-auto font-medium"
            >
              Beyond simple passwords. We use advanced entropy mathematics and real-time 
              breach database cross-referencing to quantify your digital resilience.
            </motion.p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
            {/* Password Input Column */}
            <motion.div 
              initial={{ x: -30, opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              transition={{ delay: 0.4 }}
              className="lg:col-span-7"
            >
              <Card className="glass-card overflow-hidden border-0 shadow-2xl">
                <CardHeader className="border-b border-slate-100/50 dark:border-slate-800/50 pb-8">
                  <CardTitle className="text-2xl font-black">Secure Analyzer</CardTitle>
                  <CardDescription className="text-slate-500 font-medium">
                    Test your resilience against advanced GPU brute-force attacks
                  </CardDescription>
                </CardHeader>
                <CardContent className="pt-8 space-y-8">
                  <div className="relative group">
                    <div className="absolute -inset-1 bg-gradient-to-r from-primary/20 to-emerald-500/20 rounded-2xl blur opacity-0 group-focus-within:opacity-100 transition duration-500" />
                    <div className="relative">
                      <Input
                        type={showPassword ? 'text' : 'password'}
                        placeholder="Type a password to quantify strength..."
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        className="h-16 text-xl px-6 rounded-2xl border-slate-200/60 bg-white/50 dark:bg-slate-900/50 pr-24 focus-visible:ring-primary/30"
                      />
                      <div className="absolute right-3 top-1/2 -translate-y-1/2 flex gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => setShowPassword(!showPassword)}
                          className="h-10 w-10 text-slate-400 hover:text-primary rounded-xl"
                        >
                          {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={copyPassword}
                          disabled={!password}
                          className="h-10 w-10 text-slate-400 hover:text-emerald-500 rounded-xl"
                        >
                          <Copy className="h-5 w-5" />
                        </Button>
                      </div>
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-3">
                    <Button onClick={generatePassword} variant="secondary" className="rounded-xl font-bold gap-2">
                      <RefreshCw className="h-4 w-4" /> Generate Vault-Grade
                    </Button>
                    {password && (
                      <Badge variant="outline" className="rounded-lg border-primary/20 bg-primary/5 text-primary py-2 px-4">
                        Current Entropy: {analysis?.entropy || 0} bits
                      </Badge>
                    )}
                  </div>

                  <AnimatePresence>
                    {(analysis || isChecking) && (
                      <motion.div 
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        className="space-y-8 pt-4 overflow-hidden"
                      >
                        {isChecking ? (
                          <div className="flex flex-col items-center justify-center py-12 gap-4">
                            <motion.div 
                              animate={{ rotate: 360 }}
                              transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                            >
                              <Fingerprint className="h-12 w-12 text-primary" />
                            </motion.div>
                            <span className="text-sm font-bold text-slate-500 tracking-widest uppercase">Cross-Referencing Data Breaches...</span>
                          </div>
                        ) : analysis && (
                          <div className="space-y-8">
                            {/* Strength Progress */}
                            <div className="space-y-4">
                              <div className="flex justify-between items-end">
                                <div>
                                  <p className="text-xs font-black text-slate-400 uppercase tracking-widest mb-1">Vault Resilience</p>
                                  <h3 className="text-3xl font-black" style={{ color: analysis.color }}>
                                    {analysis.strength.toUpperCase()}
                                  </h3>
                                </div>
                                <div className="text-right">
                                  <p className="text-xs font-black text-slate-400 uppercase tracking-widest mb-1">Confidence Score</p>
                                  <span className="text-2xl font-black">{analysis.score}%</span>
                                </div>
                              </div>
                              <div className="h-4 w-full bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden p-1">
                                <motion.div 
                                  initial={{ width: 0 }}
                                  animate={{ width: `${analysis.score}%` }}
                                  transition={{ duration: 0.8, ease: "circOut" }}
                                  className="h-full rounded-full shadow-lg"
                                  style={{ backgroundColor: analysis.color }}
                                />
                              </div>
                            </div>

                            {/* Breach Alert */}
                            {analysis.isBreached && (
                              <motion.div
                                initial={{ scale: 0.9, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                              >
                                <Alert variant="destructive" className="border-red-500/50 bg-red-500/5 overflow-hidden relative">
                                  <div className="absolute top-0 right-0 p-4 opacity-10">
                                    <AlertTriangle className="h-24 w-24" />
                                  </div>
                                  <AlertDescription className="relative z-10 font-bold">
                                    CRITICAL LEAK: This password was exposed in {analysis.breachCount?.toLocaleString()} identified data breaches. 
                                    Do not use this for critical accounts.
                                  </AlertDescription>
                                </Alert>
                              </motion.div>
                            )}

                            {/* Checklist */}
                            <div className="grid grid-cols-2 gap-4">
                              {[
                                { check: analysis.checks.hasLength, label: 'Min 8 Chars' },
                                { check: analysis.checks.hasUppercase, label: 'Uppercase' },
                                { check: analysis.checks.hasLowercase, label: 'Lowercase' },
                                { check: analysis.checks.hasNumbers, label: 'Numeric' },
                                { check: analysis.checks.hasSpecialChars, label: 'Symbols' },
                                { check: !analysis.checks.isCommon, label: 'Unique' }
                              ].map((item, idx) => (
                                <div key={idx} className={cn(
                                  "flex items-center gap-3 p-3 rounded-xl border transition-all",
                                  item.check ? "bg-emerald-500/5 border-emerald-500/20 text-emerald-600" : "bg-red-500/5 border-red-500/10 text-slate-400"
                                )}>
                                  {item.check ? <CheckCircle className="h-4 w-4" /> : <AlertCircle className="h-4 w-4" />}
                                  <span className="text-sm font-bold uppercase tracking-tight">{item.label}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </motion.div>
                    )}
                  </AnimatePresence>
                </CardContent>
              </Card>
            </motion.div>

            {/* Stats/Suggestions Column */}
            <motion.div 
              initial={{ x: 30, opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              transition={{ delay: 0.5 }}
              className="lg:col-span-5 space-y-6"
            >
              {/* Crack Time Card */}
              <Card className="glass-card border-slate-200/20 shadow-xl overflow-hidden group">
                <div className="absolute top-0 right-0 p-8 opacity-5 group-hover:scale-110 group-hover:rotate-12 transition-transform duration-700">
                  <Zap className="h-32 w-32 text-primary" />
                </div>
                <CardHeader>
                  <p className="text-xs font-black text-slate-400 uppercase tracking-widest mb-1">Time To Compromise</p>
                  <CardTitle className="text-4xl font-black">
                    {analysis?.crackTime || 'Instantly'}
                  </CardTitle>
                  <CardDescription className="font-medium">
                    Estimated duration for a modern GPU farm to compromise this credential.
                  </CardDescription>
                </CardHeader>
              </Card>

              {/* Suggestions */}
              <AnimatePresence>
                {analysis && analysis.suggestions.length > 0 && (
                  <motion.div
                    initial={{ y: 20, opacity: 0 }}
                    animate={{ y: 0, opacity: 1 }}
                  >
                    <Card className="glass-card border-brand-500/20 bg-brand-500/5">
                      <CardHeader className="pb-4">
                        <CardTitle className="text-sm font-black uppercase tracking-widest text-primary flex items-center gap-2">
                          <Zap className="h-4 w-4" /> Analysis Insight
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <ul className="space-y-4">
                          {analysis.suggestions.map((s, i) => (
                            <li key={i} className="flex gap-3 text-sm font-semibold text-slate-700 dark:text-slate-300">
                              <span className="text-primary">•</span> {s}
                            </li>
                          ))}
                        </ul>
                      </CardContent>
                    </Card>
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Secure Tip Card */}
              {!analysis && (
                <div className="p-8 rounded-3xl bg-black dark:bg-slate-900 shadow-2xl text-white relative overflow-hidden">
                  <div className="absolute top-0 right-0 p-4 opacity-20">
                    <Shield className="h-24 w-24 text-primary" />
                  </div>
                  <h4 className="text-xl font-black mb-4 flex items-center gap-2">
                    <Zap className="text-primary h-5 w-5 fill-primary" /> Security Tip
                  </h4>
                  <p className="text-slate-400 font-medium leading-relaxed">
                    Always use unique passwords for each service. A compromise in one location 
                    shouldn't grant access to your entire digital life.
                  </p>
                </div>
              )}
            </motion.div>
          </div>

          {/* Features Grid */}
          <div className="mt-32 grid grid-cols-1 md:grid-cols-3 gap-8">
            {[
              { icon: Zap, color: 'text-primary', title: 'Real-time Analysis', desc: 'Instant entropy calculations as you type with mathematical precision.' },
              { icon: AlertTriangle, color: 'text-emerald-500', title: 'Breach Sync', desc: 'Live cross-checks against 240+ billion exposed credentials.' },
              { icon: Fingerprint, color: 'text-indigo-500', title: 'Privacy First', desc: 'Secure k-anonymity hashing means we never see your actual password.' }
            ].map((f, i) => (
              <motion.div
                key={i}
                initial={{ y: 20, opacity: 0 }}
                whileInView={{ y: 0, opacity: 1 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.1 }}
                className="p-8 rounded-3xl glass-card text-center hover:translate-y-[-10px] transition-transform duration-300 group"
              >
                <div className={cn("inline-flex p-4 rounded-2xl bg-white dark:bg-slate-800 shadow-xl mb-6 group-hover:scale-110 transition-transform", f.color)}>
                  <f.icon className="h-8 w-8" />
                </div>
                <h3 className="text-xl font-black mb-3">{f.title}</h3>
                <p className="text-slate-500 font-medium leading-relaxed">{f.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </main>

      <footer className="container mx-auto px-6 py-12 text-center text-slate-400 font-bold text-xs uppercase tracking-widest border-t border-slate-100 dark:border-slate-800 mt-20 relative z-10 glass-card rounded-none border-x-0 border-b-0">
        © 2024 SECUREPASS VAULT PROTOCOL. ENCRYPTING THE FUTURE.
      </footer>
    </div>
  );
}

