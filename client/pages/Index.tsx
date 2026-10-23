import { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
  Eye,
  EyeOff,
  Shield,
  AlertTriangle,
  CheckCircle,
  AlertCircle,
  Copy,
  RefreshCw,
  Loader2,
  LogOut,
  User,
  Sparkles,
  Zap,
  Fingerprint,
  Check,
  BookmarkPlus,
  ShieldAlert,
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { cn } from '@/lib/utils';
import { PasswordAnalysisResponse } from '@shared/api';
import { analyzePasswordLocally } from '@shared/analysis';

export default function Index() {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [analysis, setAnalysis] = useState<PasswordAnalysisResponse | null>(null);
  const [isCheckingBreaches, setIsCheckingBreaches] = useState(false);
  const [copied, setCopied] = useState(false);
  const [historySaved, setHistorySaved] = useState(false);
  const [isSavingHistory, setIsSavingHistory] = useState(false);
  const { user, logout, isAuthenticated, isAdmin, token } = useAuth();

  const abortControllerRef = useRef<AbortController | null>(null);

  // Instant local evaluation on password change
  const handlePasswordChange = (newPwd: string) => {
    setPassword(newPwd);
    setHistorySaved(false);

    if (!newPwd) {
      setAnalysis(null);
      setIsCheckingBreaches(false);
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      return;
    }

    // Instant 0ms local mathematical evaluation
    const localResult = analyzePasswordLocally(newPwd);
    setAnalysis(localResult);
  };

  // Debounced background breach checking against Have I Been Pwned
  useEffect(() => {
    if (!password) {
      setIsCheckingBreaches(false);
      return;
    }

    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }

    const controller = new AbortController();
    abortControllerRef.current = controller;

    const timer = setTimeout(async () => {
      try {
        setIsCheckingBreaches(true);
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
        };

        if (token) {
          headers.Authorization = `Bearer ${token}`;
        }

        const response = await fetch('/api/password-analysis', {
          method: 'POST',
          headers,
          body: JSON.stringify({ password, saveToHistory: false }),
          signal: controller.signal,
        });

        if (response.ok) {
          const result: PasswordAnalysisResponse = await response.json();
          // Update analysis with upstream verified breach data and server-calculated scores
          setAnalysis((prev) => (prev ? { ...prev, ...result } : result));
        } else {
          // If server returns error, preserve local analysis and mark breach status unavailable
          setAnalysis((prev) =>
            prev ? { ...prev, breachStatus: 'unavailable', isBreached: false } : null
          );
        }
      } catch (err: any) {
        if (err.name !== 'AbortError') {
          console.warn('Breach lookup warning:', err);
          setAnalysis((prev) =>
            prev ? { ...prev, breachStatus: 'unavailable', isBreached: false } : null
          );
        }
      } finally {
        setIsCheckingBreaches(false);
      }
    }, 450);

    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [password, token]);

  const generatePassword = () => {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let result = '';
    const length = 18;
    for (let i = 0; i < length; i++) {
      result += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    handlePasswordChange(result);
  };

  const copyPassword = () => {
    if (!password) return;
    navigator.clipboard.writeText(password);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSaveToHistory = async () => {
    if (!password || !isAuthenticated || isSavingHistory) return;
    try {
      setIsSavingHistory(true);
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };
      if (token) {
        headers.Authorization = `Bearer ${token}`;
      }

      const res = await fetch('/api/password-analysis', {
        method: 'POST',
        headers,
        body: JSON.stringify({ password, saveToHistory: true }),
      });

      if (res.ok) {
        setHistorySaved(true);
      }
    } catch (err) {
      console.error('Failed to save to history:', err);
    } finally {
      setIsSavingHistory(false);
    }
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
              <a href="#analyzer" className="text-sm font-semibold hover:text-primary transition-colors">Analyzer</a>
              <a href="#features" className="text-sm font-semibold hover:text-primary transition-colors">Security Model</a>
              <Link to="/login" className="text-sm font-semibold hover:text-primary transition-colors">Vault</Link>
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
                  <Button variant="ghost" size="icon" onClick={logout} className="rounded-full" title="Sign Out">
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
          <div className="text-center mb-16">
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ delay: 0.1 }}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 text-xs font-bold mb-6 border border-emerald-500/20"
            >
              <Sparkles className="h-3 w-3" />
              LIVE BREACH INTELLIGENCE ACTIVE (K-ANONYMITY RANGE SYNC)
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
              Real-time entropy mathematics and zero-knowledge k-anonymity breach cross-referencing. 
              Quantify your cryptographic resilience with instant feedback.
            </motion.p>
          </div>

          <div id="analyzer" className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
            {/* Password Input Column */}
            <motion.div 
              initial={{ x: -30, opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              transition={{ delay: 0.4 }}
              className="lg:col-span-7"
            >
              <Card className="glass-card overflow-hidden border-0 shadow-2xl">
                <CardHeader className="border-b border-slate-100/50 dark:border-slate-800/50 pb-8">
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="text-2xl font-black">Secure Analyzer</CardTitle>
                      <CardDescription className="text-slate-500 font-medium mt-1">
                        Live resilience test against high-speed GPU cluster attacks
                      </CardDescription>
                    </div>
                    {isCheckingBreaches && (
                      <Badge variant="outline" className="animate-pulse bg-primary/10 border-primary/30 text-primary text-xs flex items-center gap-1.5 py-1 px-3">
                        <Loader2 className="h-3 w-3 animate-spin" />
                        <span>Verifying Breaches</span>
                      </Badge>
                    )}
                  </div>
                </CardHeader>

                <CardContent className="pt-8 space-y-8">
                  <div className="relative group">
                    <div className="absolute -inset-1 bg-gradient-to-r from-primary/20 to-emerald-500/20 rounded-2xl blur opacity-0 group-focus-within:opacity-100 transition duration-500" />
                    <div className="relative">
                      <Input
                        id="password-input"
                        type={showPassword ? 'text' : 'password'}
                        placeholder="Type a password to quantify resilience..."
                        value={password}
                        onChange={(e) => handlePasswordChange(e.target.value)}
                        className="h-16 text-xl px-6 rounded-2xl border-slate-200/60 bg-white/50 dark:bg-slate-900/50 pr-24 focus-visible:ring-primary/30 font-mono tracking-wide"
                      />
                      <div className="absolute right-3 top-1/2 -translate-y-1/2 flex gap-1">
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          onClick={() => setShowPassword(!showPassword)}
                          className="h-10 w-10 text-slate-400 hover:text-primary rounded-xl"
                          title={showPassword ? "Hide password" : "Show password"}
                        >
                          {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                        </Button>
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          onClick={copyPassword}
                          disabled={!password}
                          className="h-10 w-10 text-slate-400 hover:text-emerald-500 rounded-xl"
                          title="Copy to clipboard"
                        >
                          {copied ? <Check className="h-5 w-5 text-emerald-500" /> : <Copy className="h-5 w-5" />}
                        </Button>
                      </div>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex flex-wrap gap-2">
                      <Button onClick={generatePassword} variant="secondary" className="rounded-xl font-bold gap-2 shadow-sm">
                        <RefreshCw className="h-4 w-4" /> Generate Vault-Grade
                      </Button>
                      {isAuthenticated && password && (
                        <Button 
                          onClick={handleSaveToHistory} 
                          variant="outline" 
                          disabled={isSavingHistory || historySaved}
                          className={cn(
                            "rounded-xl font-bold gap-2 transition-all",
                            historySaved ? "border-emerald-500/40 text-emerald-600 bg-emerald-500/10" : ""
                          )}
                        >
                          {historySaved ? (
                            <>
                              <Check className="h-4 w-4 text-emerald-600" /> Saved to Vault
                            </>
                          ) : (
                            <>
                              <BookmarkPlus className="h-4 w-4" /> Save to Vault History
                            </>
                          )}
                        </Button>
                      )}
                    </div>
                    {password && analysis && (
                      <Badge variant="outline" className="rounded-lg border-primary/20 bg-primary/5 text-primary py-1.5 px-3 font-mono font-bold text-xs">
                        Entropy: {analysis.entropy} bits
                      </Badge>
                    )}
                  </div>

                  {/* Analyzer View: Active Analysis vs Inviting Ready State */}
                  <AnimatePresence mode="wait">
                    {analysis ? (
                      <motion.div 
                        key="analysis-results"
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -10 }}
                        transition={{ duration: 0.2 }}
                        className="space-y-6 pt-2"
                      >
                        {/* Strength Progress */}
                        <div className="space-y-4">
                          <div className="flex justify-between items-end">
                            <div>
                              <p className="text-xs font-black text-slate-400 uppercase tracking-widest mb-1">Vault Resilience</p>
                              <h3 className="text-3xl font-black transition-colors duration-300" style={{ color: analysis.color }}>
                                {analysis.strength.toUpperCase()}
                              </h3>
                            </div>
                            <div className="text-right">
                              <p className="text-xs font-black text-slate-400 uppercase tracking-widest mb-1">Confidence Score</p>
                              <span className="text-2xl font-black">{analysis.score}%</span>
                            </div>
                          </div>
                          <div className="h-4 w-full bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden p-1 shadow-inner">
                            <motion.div 
                              initial={{ width: 0 }}
                              animate={{ width: `${Math.max(4, analysis.score)}%` }}
                              transition={{ duration: 0.4, ease: "easeOut" }}
                              className="h-full rounded-full shadow-md transition-colors duration-300"
                              style={{ backgroundColor: analysis.color }}
                            />
                          </div>
                        </div>

                        {/* Breach Status Banner */}
                        {analysis.breachStatus === 'breached' && (
                          <motion.div
                            initial={{ scale: 0.98, opacity: 0 }}
                            animate={{ scale: 1, opacity: 1 }}
                          >
                            <Alert variant="destructive" className="border-red-500/50 bg-red-500/10 overflow-hidden relative">
                              <div className="absolute top-0 right-0 p-4 opacity-10">
                                <AlertTriangle className="h-20 w-20" />
                              </div>
                              <AlertDescription className="relative z-10 font-bold text-red-600 dark:text-red-400 leading-relaxed">
                                🚨 CRITICAL LEAK: This credential was identified in{' '}
                                <span className="underline font-black">{analysis.breachCount?.toLocaleString()}</span> known
                                data breaches. Do not use this password for any account.
                              </AlertDescription>
                            </Alert>
                          </motion.div>
                        )}

                        {analysis.breachStatus === 'unavailable' && (
                          <motion.div
                            initial={{ scale: 0.98, opacity: 0 }}
                            animate={{ scale: 1, opacity: 1 }}
                          >
                            <Alert className="border-amber-500/30 bg-amber-500/5 text-amber-700 dark:text-amber-300">
                              <AlertCircle className="h-4 w-4 text-amber-500" />
                              <AlertDescription className="font-semibold text-xs">
                                Live Breach Intelligence Offline: Upstream database is temporarily unreachable. Resilience score is evaluated strictly via offline algorithmic heuristics.
                              </AlertDescription>
                            </Alert>
                          </motion.div>
                        )}

                        {analysis.breachStatus === 'clean' && !isCheckingBreaches && (
                          <div className="flex items-center gap-2 p-3 rounded-xl border border-emerald-500/20 bg-emerald-500/5 text-emerald-600 dark:text-emerald-400 text-xs font-bold">
                            <CheckCircle className="h-4 w-4 flex-shrink-0" />
                            <span>Zero Leaks Detected: Not found in the 800M+ pwned passwords database</span>
                          </div>
                        )}

                        {/* Checklist */}
                        <div className="grid grid-cols-2 gap-3">
                          {[
                            { check: analysis.checks.hasLength, label: 'Min 8 Chars' },
                            { check: analysis.checks.hasUppercase, label: 'Uppercase' },
                            { check: analysis.checks.hasLowercase, label: 'Lowercase' },
                            { check: analysis.checks.hasNumbers, label: 'Numeric' },
                            { check: analysis.checks.hasSpecialChars, label: 'Symbols' },
                            { check: !analysis.checks.isCommon, label: 'Unique' },
                          ].map((item, idx) => (
                            <div
                              key={idx}
                              className={cn(
                                "flex items-center gap-3 p-3 rounded-xl border transition-all duration-200",
                                item.check
                                  ? "bg-emerald-500/5 border-emerald-500/20 text-emerald-600 dark:text-emerald-400"
                                  : "bg-slate-50 dark:bg-slate-800/40 border-slate-200/50 dark:border-slate-700/50 text-slate-400"
                              )}
                            >
                              {item.check ? (
                                <CheckCircle className="h-4 w-4 flex-shrink-0 text-emerald-500" />
                              ) : (
                                <AlertCircle className="h-4 w-4 flex-shrink-0 text-slate-400" />
                              )}
                              <span className="text-xs font-bold uppercase tracking-tight">{item.label}</span>
                            </div>
                          ))}
                        </div>
                      </motion.div>
                    ) : (
                      /* Welcoming Initial Empty State */
                      <motion.div
                        key="ready-state"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="p-8 rounded-2xl border border-dashed border-slate-200 dark:border-slate-800 text-center space-y-4"
                      >
                        <div className="w-12 h-12 rounded-2xl bg-primary/10 text-primary flex items-center justify-center mx-auto shadow-inner">
                          <Fingerprint className="h-6 w-6" />
                        </div>
                        <div>
                          <h4 className="text-base font-bold text-slate-900 dark:text-white">Ready for Analysis</h4>
                          <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1 leading-relaxed">
                            Type any password above or click <strong>Generate Vault-Grade</strong> to instantly compute entropy, estimate GPU brute-force times, and verify leak status.
                          </p>
                        </div>
                        <div className="flex justify-center gap-2 pt-2">
                          <Button 
                            variant="outline" 
                            size="sm" 
                            onClick={() => handlePasswordChange('Correct-Horse-Battery-Staple-2026!')}
                            className="text-xs font-semibold rounded-lg"
                          >
                            Try Passphrase Example
                          </Button>
                        </div>
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
                    {analysis ? analysis.crackTime : '—'}
                  </CardTitle>
                  <CardDescription className="font-medium text-xs mt-2 leading-relaxed">
                    {analysis?.timeToCrack?.scenario ||
                      'Mathematical model based on offline GPU cluster performing 1 billion hash attempts per second.'}
                  </CardDescription>
                </CardHeader>
              </Card>

              {/* Suggestions */}
              <AnimatePresence>
                {analysis && analysis.suggestions && analysis.suggestions.length > 0 && (
                  <motion.div
                    initial={{ y: 20, opacity: 0 }}
                    animate={{ y: 0, opacity: 1 }}
                    exit={{ y: 20, opacity: 0 }}
                  >
                    <Card className="glass-card border-brand-500/20 bg-brand-500/5">
                      <CardHeader className="pb-3">
                        <CardTitle className="text-xs font-black uppercase tracking-widest text-primary flex items-center gap-2">
                          <Zap className="h-4 w-4" /> Optimization Recommendations
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <ul className="space-y-3">
                          {analysis.suggestions.map((s, i) => (
                            <li key={i} className="flex gap-2.5 text-xs font-semibold text-slate-700 dark:text-slate-300 leading-snug">
                              <span className="text-primary font-bold">•</span>
                              <span>{s}</span>
                            </li>
                          ))}
                        </ul>
                      </CardContent>
                    </Card>
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Secure Tip Card when no password entered */}
              {!analysis && (
                <div className="p-8 rounded-3xl bg-slate-900 shadow-2xl text-white relative overflow-hidden border border-slate-800">
                  <div className="absolute top-0 right-0 p-4 opacity-15">
                    <ShieldAlert className="h-24 w-24 text-primary" />
                  </div>
                  <h4 className="text-lg font-black mb-3 flex items-center gap-2 text-white">
                    <Zap className="text-primary h-5 w-5 fill-primary" /> Security Principle
                  </h4>
                  <p className="text-slate-300 text-sm font-medium leading-relaxed">
                    Length beats complexity. A 16-character passphrase composed of distinct random words offers higher cryptographic work factor than an 8-character mixed string.
                  </p>
                </div>
              )}
            </motion.div>
          </div>

          {/* Features Grid */}
          <div id="features" className="mt-28 grid grid-cols-1 md:grid-cols-3 gap-8">
            {[
              {
                icon: Zap,
                color: 'text-primary',
                title: 'Instant 0ms Telemetry',
                desc: 'Client-side mathematical Shannon entropy evaluation with zero keystroke lag.',
              },
              {
                icon: AlertTriangle,
                color: 'text-emerald-500',
                title: 'K-Anonymity Breach Sync',
                desc: 'Private 5-character SHA-1 range queries ensure your password is never exposed over the wire.',
              },
              {
                icon: Fingerprint,
                color: 'text-indigo-500',
                title: 'Zero Password Storage',
                desc: 'Neither plain passwords nor unsalted hashes are ever persisted in databases or server logs.',
              },
            ].map((f, i) => (
              <motion.div
                key={i}
                initial={{ y: 20, opacity: 0 }}
                whileInView={{ y: 0, opacity: 1 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.1 }}
                className="p-8 rounded-3xl glass-card text-center hover:translate-y-[-6px] transition-transform duration-300 group"
              >
                <div className={cn("inline-flex p-4 rounded-2xl bg-white dark:bg-slate-800 shadow-xl mb-6 group-hover:scale-110 transition-transform", f.color)}>
                  <f.icon className="h-7 w-7" />
                </div>
                <h3 className="text-lg font-black mb-2">{f.title}</h3>
                <p className="text-slate-500 text-sm font-medium leading-relaxed">{f.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </main>

      <footer className="container mx-auto px-6 py-12 text-center text-slate-400 font-bold text-xs uppercase tracking-widest border-t border-slate-100 dark:border-slate-800 mt-20 relative z-10 glass-card rounded-none border-x-0 border-b-0">
        © 2026 SECUREPASS VAULT PROTOCOL. ZERO-KNOWLEDGE RESILIENCE PLATFORM.
      </footer>
    </div>
  );
}
