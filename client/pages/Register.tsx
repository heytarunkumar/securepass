import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Mail, Lock, Eye, EyeOff, User, ArrowLeft, Sparkles, Fingerprint } from 'lucide-react';
import { motion } from 'framer-motion';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Checkbox } from '@/components/ui/checkbox';

export default function Register() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [acceptTerms, setAcceptTerms] = useState(false);
  const [error, setError] = useState('');
  const { register, isLoading, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/');
    }
  }, [isAuthenticated, navigate]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (password !== confirmPassword) {
      setError('Passwords do not match!');
      return;
    }

    if (!acceptTerms) {
      setError('Please accept the terms of service');
      return;
    }

    const result = await register(email, password, confirmPassword);
    if (!result.success) {
      setError(result.message);
    }
  };

  return (
    <div className="min-h-screen premium-gradient-bg relative flex flex-col overflow-hidden font-sans">
      <div className="hero-glow" />
      <div className="hero-glow-alt" />

      {/* Header */}
      <motion.header 
        initial={{ y: -20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        className="glass-header z-50 px-6 py-4"
      >
        <div className="container mx-auto flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3">
            <div className="p-2 bg-primary rounded-xl shadow-lg shadow-primary/20">
              <Shield className="h-6 w-6 text-white" />
            </div>
            <h1 className="text-xl font-black tracking-tight text-slate-900 dark:text-white uppercase">
              Secure<span className="text-primary italic">Pass</span>
            </h1>
          </Link>
          <Button variant="ghost" size="sm" asChild className="rounded-full gap-2 font-bold">
            <Link to="/">
              <ArrowLeft className="h-4 w-4" /> Back to Analyzer
            </Link>
          </Button>
        </div>
      </motion.header>

      {/* Main Content */}
      <main className="flex-1 flex items-center justify-center p-6 relative z-10">
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          className="w-full max-w-md"
        >
          <Card className="glass-card border-0 shadow-2xl relative overflow-hidden">
            <div className="absolute top-0 right-0 p-8 opacity-5">
              <User className="h-32 w-32 text-primary" />
            </div>
            
            <CardHeader className="text-center pt-10 pb-6">
              <motion.div
                initial={{ y: 10, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                transition={{ delay: 0.1 }}
                className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 text-primary text-[10px] font-black mb-4 uppercase tracking-[0.2em]"
              >
                <Sparkles className="h-3 w-3" />
                Initialize Vault
              </motion.div>
              <CardTitle className="text-3xl font-black tracking-tight">Create Account</CardTitle>
              <CardDescription className="text-slate-500 font-medium pt-2">
                Join our secure protocol to track your security evolution.
              </CardDescription>
            </CardHeader>
            
            <CardContent className="px-8 pb-10">
              <form onSubmit={handleSubmit} className="space-y-6">
                <div className="space-y-2">
                  <Label htmlFor="email" className="text-[10px] font-black uppercase tracking-widest text-slate-400 ml-1">Identity (Email)</Label>
                  <div className="relative group">
                    <Mail className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-400 group-focus-within:text-primary transition-colors" />
                    <Input
                      id="email"
                      type="email"
                      placeholder="vault-keeper@protocol.com"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="h-14 pl-12 rounded-xl bg-white/50 dark:bg-slate-900/50 border-slate-200/60 focus-visible:ring-primary/20"
                      required
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="password" className="text-[10px] font-black uppercase tracking-widest text-slate-400 ml-1">Master Key (Password)</Label>
                  <div className="relative group">
                    <Lock className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-400 group-focus-within:text-primary transition-colors" />
                    <Input
                      id="password"
                      type={showPassword ? 'text' : 'password'}
                      placeholder="••••••••••••"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="h-14 pl-12 pr-12 rounded-xl bg-white/50 dark:bg-slate-900/50 border-slate-200/60 focus-visible:ring-primary/20"
                      required
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-2 top-1/2 -translate-y-1/2 h-10 w-10 text-slate-400 hover:text-primary rounded-lg"
                    >
                      {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                    </Button>
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="confirmPassword" className="text-[10px] font-black uppercase tracking-widest text-slate-400 ml-1">Verify Key</Label>
                  <div className="relative">
                    <Lock className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-400" />
                    <Input
                      id="confirmPassword"
                      type={showPassword ? 'text' : 'password'}
                      placeholder="Repeat master key"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      className="h-14 pl-12 rounded-xl bg-white/50 dark:bg-slate-900/50 border-slate-200/60 focus-visible:ring-primary/20"
                      required
                    />
                  </div>
                </div>

                <div className="flex items-center space-x-3 px-1">
                  <Checkbox 
                    id="terms" 
                    checked={acceptTerms}
                    onCheckedChange={(checked) => setAcceptTerms(checked as boolean)}
                    className="border-slate-300 data-[state=checked]:bg-primary rounded-md"
                  />
                  <Label htmlFor="terms" className="text-[10px] font-bold text-slate-500 leading-tight">
                    I acknowledge and agree to the <span className="text-primary hover:underline cursor-pointer">Protocol Terms</span> and <span className="text-primary hover:underline cursor-pointer">Privacy Framework</span>.
                  </Label>
                </div>

                {error && (
                  <motion.div initial={{ y: -10, opacity: 0 }} animate={{ y: 0, opacity: 1 }}>
                    <Alert variant="destructive" className="bg-red-500/5 border-red-500/10 rounded-xl">
                      <AlertDescription className="font-bold text-xs text-center">{error}</AlertDescription>
                    </Alert>
                  </motion.div>
                )}

                <Button type="submit" className="w-full h-14 rounded-xl shadow-xl shadow-primary/20 font-black uppercase tracking-widest transition-all hover:scale-[1.02] active:scale-[0.98]" disabled={isLoading || !acceptTerms}>
                  {isLoading ? (
                    <div className="flex items-center gap-2">
                      <Fingerprint className="h-5 w-5 animate-pulse" />
                      Creating Vault...
                    </div>
                  ) : 'Initialize Access'}
                </Button>

                <div className="pt-4 text-center">
                  <Link to="/login" className="text-xs font-bold text-slate-500 hover:text-primary transition-colors">
                    Already have a vault? <span className="text-primary underline decoration-2 underline-offset-4">Authenticate Here</span>
                  </Link>
                </div>
              </form>
            </CardContent>
          </Card>
        </motion.div>
      </main>

      <footer className="p-8 text-center text-slate-400 font-extrabold text-[8px] uppercase tracking-[0.3em] opacity-40">
        Vault Initialization Active // Security Peer Review Req.
      </footer>
    </div>
  );
}

