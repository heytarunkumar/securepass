import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Users, AlertTriangle, BarChart3, Eye, Settings, LogOut, User, Trash2, ArrowLeft, Zap, ShieldCheck, Activity, Database } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import { cn } from '@/lib/utils';

interface AdminStats {
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

interface AdminUser {
  id: string;
  email: string;
  role: string;
  createdAt: string;
  lastLogin: string | null;
  isActive: boolean;
  passwordCount: number;
}

export default function AdminDashboard() {
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const { user: currentUser, logout, isAdmin, token } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!isAdmin) {
      navigate('/');
    }
  }, [isAdmin, navigate]);

  useEffect(() => {
    if (!token || !isAdmin) return;

    const fetchAdminData = async () => {
      try {
        const headers = {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        };

        const statsResponse = await fetch('/api/admin/stats', { headers });
        if (statsResponse.ok) {
          const statsData = await statsResponse.json();
          setStats(statsData.stats);
        }

        const usersResponse = await fetch('/api/admin/users', { headers });
        if (usersResponse.ok) {
          const usersData = await usersResponse.json();
          setUsers(usersData.users);
        }
      } catch (error) {
        console.error('Error fetching admin data:', error);
        setError('Failed to load admin data');
      } finally {
        setIsLoading(false);
      }
    };

    fetchAdminData();
  }, [token, isAdmin]);

  const handleUserStatusToggle = async (userId: string, isActive: boolean) => {
    try {
      const response = await fetch(`/api/admin/users/${userId}/status`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ isActive: !isActive }),
      });

      if (response.ok) {
        setUsers(users.map(u =>
          u.id === userId ? { ...u, isActive: !isActive } : u
        ));
      }
    } catch (error) {
      console.error('Error updating user status:', error);
    }
  };

  const handleDeleteUser = async (userId: string) => {
    if (!confirm('Are you sure you want to delete this user?')) return;

    try {
      const response = await fetch(`/api/admin/users/${userId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        setUsers(users.filter(u => u.id !== userId));
        if (stats) {
          setStats({ ...stats, totalUsers: stats.totalUsers - 1 });
        }
      }
    } catch (error) {
      console.error('Error deleting user:', error);
    }
  };

  if (!isAdmin) return null;

  if (isLoading) {
    return (
      <div className="min-h-screen premium-gradient-bg flex items-center justify-center">
        <div className="text-center">
          <motion.div animate={{ rotate: 360 }} transition={{ duration: 1, repeat: Infinity, ease: "linear" }}>
            <Activity className="h-12 w-12 text-primary mx-auto mb-4" />
          </motion.div>
          <p className="font-black text-slate-500 uppercase tracking-widest text-[10px]">Syncing Control Center...</p>
        </div>
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
            <Link to="/" className="flex items-center gap-3 group">
              <div className="p-2 bg-primary rounded-xl shadow-lg shadow-primary/20 group-hover:scale-110 transition-transform">
                <Shield className="h-6 w-6 text-white" />
              </div>
              <h1 className="text-xl font-black tracking-tight text-slate-900 dark:text-white uppercase">
                SECURE<span className="text-primary italic">PASS</span> <span className="text-[10px] bg-slate-900 text-white px-2 py-1 rounded ml-2">ADMIN</span>
              </h1>
            </Link>
            
            <div className="flex items-center gap-4">
              <Button variant="ghost" size="sm" asChild className="rounded-full gap-2 font-bold hover:bg-white/40">
                <Link to="/">
                  <ArrowLeft className="h-4 w-4" /> Exit to Labs
                </Link>
              </Button>
              <div className="h-6 w-px bg-slate-200 dark:bg-slate-700 mx-2" />
              <div className="flex items-center gap-3">
                <div className="text-right hidden sm:block">
                  <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest leading-none">Logged as</p>
                  <p className="text-xs font-bold">{currentUser?.email}</p>
                </div>
                <Button variant="ghost" size="icon" onClick={logout} className="rounded-full hover:bg-red-500/10 hover:text-red-500 transition-colors">
                  <LogOut className="h-5 w-5" />
                </Button>
              </div>
            </div>
          </div>
        </div>
      </motion.header>

      {/* Main Content */}
      <main className="container mx-auto px-6 py-12 relative z-10">
        <div className="max-w-7xl mx-auto">
          {/* Page Header */}
          <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 mb-12">
            <div>
              <motion.div initial={{ x: -20, opacity: 0 }} animate={{ x: 0, opacity: 1 }} className="flex items-center gap-2 mb-4">
                <div className="h-1 w-8 bg-primary rounded-full" />
                <span className="text-[10px] font-black uppercase tracking-[0.2em] text-primary">System Oversight</span>
              </motion.div>
              <motion.h2 initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.1 }} className="text-4xl md:text-5xl font-black text-slate-900 dark:text-white tracking-tight">
                Control <span className="text-primary underline decoration-emerald-500 decoration-4 underline-offset-8">Dashboard</span>
              </motion.h2>
            </div>
            {stats && (
              <Badge variant="outline" className="h-10 px-4 rounded-xl border-emerald-500/20 bg-emerald-500/5 text-emerald-600 font-bold gap-2">
                <ShieldCheck className="h-4 w-4" /> ALL SYSTEMS NOMINAL
              </Badge>
            )}
          </div>

          {error && (
            <Alert variant="destructive" className="mb-8 glass-card border-red-500/50 bg-red-500/5">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription className="font-bold">{error}</AlertDescription>
            </Alert>
          )}

          {/* Stats Grid */}
          {stats && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
              {[
                { title: 'Registered Entities', value: stats.totalUsers, icon: Users, color: 'text-blue-500', bg: 'bg-blue-500/10' },
                { title: 'Analysis Cycles', value: stats.totalPasswordsChecked, icon: Activity, color: 'text-primary', bg: 'bg-primary/10' },
                { title: 'Compromised Keys', value: stats.breachedPasswordsFound, icon: AlertTriangle, color: 'text-red-500', bg: 'bg-red-500/10' },
                { title: 'Avg. Resilience', value: `${stats.averagePasswordStrength}%`, icon: BarChart3, color: 'text-emerald-500', bg: 'bg-emerald-500/10' }
              ].map((s, i) => (
                <motion.div key={i} initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.1 * i }}>
                  <Card className="glass-card border-0 shadow-xl group hover:scale-[1.02] transition-transform">
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                      <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest">{s.title}</p>
                      <div className={cn("p-2 rounded-lg transition-colors", s.bg, s.color)}>
                        <s.icon className="h-4 w-4" />
                      </div>
                    </CardHeader>
                    <CardContent className="pt-4">
                      <div className="text-3xl font-black tracking-tight">{s.value.toLocaleString()}</div>
                    </CardContent>
                  </Card>
                </motion.div>
              ))}
            </div>
          )}

          {/* User Management */}
          <motion.div initial={{ y: 30, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.4 }}>
            <Card className="glass-card border-0 shadow-2xl overflow-hidden">
              <CardHeader className="border-b border-white/10 pb-8 bg-white/20 dark:bg-slate-900/20">
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-2xl font-black flex items-center gap-2">
                      Entity Management
                    </CardTitle>
                    <CardDescription className="font-medium text-slate-500">
                      Operator permissions and access synchronization controls.
                    </CardDescription>
                  </div>
                  <div className="p-3 bg-slate-900/10 dark:bg-white/10 rounded-2xl">
                    <Database className="h-6 w-6" />
                  </div>
                </div>
              </CardHeader>
              <CardContent className="p-0">
                {users.length > 0 ? (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="bg-slate-50/50 dark:bg-slate-900/20 border-b border-white/10">
                          <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest text-slate-400">Email</th>
                          <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest text-slate-400">Protocol Role</th>
                          <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest text-slate-400">Initialization</th>
                          <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest text-slate-400">Last Sync</th>
                          <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest text-slate-400">Status</th>
                          <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest text-slate-400 text-right">Operations</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/10">
                        {users.map((u, i) => (
                          <motion.tr key={u.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 * i + 0.5 }} className="group hover:bg-white/30 dark:hover:bg-slate-800/30 transition-colors">
                            <td className="px-8 py-5 font-bold text-sm tracking-tight">{u.email}</td>
                            <td className="px-8 py-5">
                              <Badge variant={u.role === 'admin' ? 'default' : 'secondary'} className="rounded-md font-black uppercase text-[9px] tracking-widest">
                                {u.role}
                              </Badge>
                            </td>
                            <td className="px-8 py-5 text-xs font-semibold text-slate-500">{new Date(u.createdAt).toLocaleDateString()}</td>
                            <td className="px-8 py-5 text-xs font-semibold text-slate-500">{u.lastLogin ? new Date(u.lastLogin).toLocaleDateString() : '—'}</td>
                            <td className="px-8 py-5">
                              <div className="flex items-center gap-2">
                                <div className={cn("h-2 w-2 rounded-full", u.isActive ? "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]" : "bg-red-500")} />
                                <span className="text-[10px] font-black uppercase tracking-widest">{u.isActive ? 'Active' : 'Revoked'}</span>
                              </div>
                            </td>
                            <td className="px-8 py-5 text-right">
                              <div className="flex justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                <Button size="sm" variant="outline" onClick={() => handleUserStatusToggle(u.id, u.isActive)} disabled={u.id === currentUser?.id} className="h-8 rounded-lg text-[10px] font-black uppercase tracking-tighter bg-white/50 border-slate-200">
                                  {u.isActive ? 'Revoke Access' : 'Authorize'}
                                </Button>
                                <Button size="icon" variant="destructive" onClick={() => handleDeleteUser(u.id)} disabled={u.id === currentUser?.id} className="h-8 w-8 rounded-lg shadow-lg shadow-red-500/20">
                                  <Trash2 className="h-4 w-4" />
                                </Button>
                              </div>
                            </td>
                          </motion.tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="text-center py-20 px-6">
                    <Users className="h-16 w-16 mx-auto mb-6 text-slate-200" />
                    <h3 className="text-xl font-black mb-2">Registry Empty</h3>
                    <p className="text-slate-500 font-medium">No operators have been registered in the system yet.</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </motion.div>
        </div>
      </main>

      <footer className="container mx-auto px-6 py-12 text-center text-slate-400 font-extrabold text-[8px] uppercase tracking-[0.3em] opacity-40 border-t border-white/10 mt-20 relative z-10">
        Control Center Secure Bridge // Root Access ID: SC-ADMIN-001
      </footer>
    </div>
  );
}

