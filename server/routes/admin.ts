import { RequestHandler } from 'express';
import {
  userDb,
  passwordCheckDb,
  passwordHistoryDb,
  adminAuditDb,
  sessionDb
} from '../database';
import { AuthRequest } from '../auth';
import { AdminStats } from '@shared/api';

// Get admin dashboard statistics
export const handleAdminStats: RequestHandler = async (_req: AuthRequest, res) => {
  try {
    const totalUsers = userDb.getCount();
    const totalPasswordsChecked = passwordCheckDb.getCount();
    const breachedPasswordsFound = passwordCheckDb.getBreachedCount();
    const averagePasswordStrength = passwordCheckDb.getAverageStrength();

    const strengthDistribution = passwordCheckDb.getStrengthDistribution();
    const distributionMap: AdminStats['strengthDistribution'] = {
      'Very Weak': 0,
      'Weak': 0,
      'Fair': 0,
      'Good': 0,
      'Strong': 0,
      'Very Strong': 0,
    };

    strengthDistribution.forEach((item: any) => {
      if (item.strength_level in distributionMap) {
        distributionMap[item.strength_level as keyof typeof distributionMap] = item.count;
      }
    });

    const stats: AdminStats = {
      totalUsers: totalUsers.count,
      totalPasswordsChecked: totalPasswordsChecked.count,
      breachedPasswordsFound: breachedPasswordsFound.count,
      averagePasswordStrength,
      strengthDistribution: distributionMap,
    };

    res.json({
      success: true,
      stats,
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch admin statistics',
    });
  }
};

// Get all users (SP-12: Accurate MFA status)
export const handleGetUsers: RequestHandler = async (_req: AuthRequest, res) => {
  try {
    const users = userDb.getAll();

    const usersWithStats = users.map((user: any) => {
      const passwordHistory = passwordHistoryDb.getByUser(user.id);
      return {
        id: user.id,
        email: user.email,
        role: user.role,
        createdAt: user.created_at,
        lastLogin: user.last_login,
        isActive: user.is_active === 1,
        twoFactorEnabled: false, // SP-12: Accurately reflected until verified enrollment
        passwordCount: passwordHistory.length,
        lastPasswordCheck: passwordHistory[0]?.created_at || null,
      };
    });

    res.json({
      success: true,
      users: usersWithStats,
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch users',
    });
  }
};

// Update user status (SP-13: Audited mutation + safeguard against disabling last admin)
export const handleUpdateUserStatus: RequestHandler = async (req: AuthRequest, res) => {
  try {
    const { userId } = req.params;
    const { isActive } = req.body;

    if (typeof isActive !== 'boolean') {
      return res.status(400).json({
        success: false,
        message: 'isActive must be a boolean value',
      });
    }

    // Don't allow admins to deactivate themselves
    if (userId === req.user?.id && !isActive) {
      return res.status(400).json({
        success: false,
        message: 'You cannot deactivate your own administrative account',
      });
    }

    const targetUser = userDb.findAnyById(userId);
    if (!targetUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    // SP-13: Guard against deactivating the last remaining active administrator
    if (!isActive && targetUser.role === 'admin') {
      const activeAdminCount = userDb.countActiveAdmins();
      if (activeAdminCount <= 1) {
        return res.status(400).json({
          success: false,
          message: 'Operation rejected: Cannot deactivate the last remaining active administrator',
        });
      }
    }

    userDb.updateStatus(userId, isActive);

    // SP-05: If deactivated, revoke all existing sessions immediately
    if (!isActive) {
      sessionDb.revokeAllForUser(userId);
    }

    // SP-13: Audit log the status update
    adminAuditDb.log(
      req.user!.id,
      req.user!.email,
      isActive ? 'USER_ACTIVATE' : 'USER_DEACTIVATE',
      'user',
      userId,
      JSON.stringify({ previousStatus: targetUser.is_active === 1, newStatus: isActive, targetEmail: targetUser.email }),
      req.ip || null
    );

    res.json({
      success: true,
      message: `User ${isActive ? 'activated' : 'deactivated'} successfully`,
    });
  } catch (error) {
    console.error('Update user status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update user status',
    });
  }
};

// Delete user (SP-13: Audited mutation + safeguard against deleting last admin)
export const handleDeleteUser: RequestHandler = async (req: AuthRequest, res) => {
  try {
    const { userId } = req.params;

    // Don't allow admins to delete themselves
    if (userId === req.user?.id) {
      return res.status(400).json({
        success: false,
        message: 'You cannot delete your own administrative account',
      });
    }

    const targetUser = userDb.findAnyById(userId);
    if (!targetUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    // SP-13: Guard against deleting the last remaining active administrator
    if (targetUser.role === 'admin') {
      const activeAdminCount = userDb.countActiveAdmins();
      if (activeAdminCount <= 1) {
        return res.status(400).json({
          success: false,
          message: 'Operation rejected: Cannot delete the last remaining active administrator',
        });
      }
    }

    // Revoke all sessions
    sessionDb.revokeAllForUser(userId);
    userDb.delete(userId);

    // SP-13: Audit log deletion
    adminAuditDb.log(
      req.user!.id,
      req.user!.email,
      'USER_DELETE',
      'user',
      userId,
      JSON.stringify({ deletedEmail: targetUser.email, deletedRole: targetUser.role }),
      req.ip || null
    );

    res.json({
      success: true,
      message: 'User deleted successfully',
    });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete user',
    });
  }
};

// Get user details
export const handleGetUserDetails: RequestHandler = async (req: AuthRequest, res) => {
  try {
    const { userId } = req.params;

    const user = userDb.findAnyById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    const passwordHistory = passwordHistoryDb.getByUser(userId);

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        createdAt: user.created_at,
        lastLogin: user.last_login,
        isActive: user.is_active === 1,
        twoFactorEnabled: false, // SP-12
        passwordHistory: passwordHistory.map((p) => ({
          id: p.id,
          strength: p.strength_level,
          score: p.strength_score,
          entropy: p.entropy,
          isBreached: p.is_breached === 1,
          breachCount: p.breach_count,
          createdAt: p.created_at,
        })),
      },
    });
  } catch (error) {
    console.error('Get user details error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch user details',
    });
  }
};

// Get admin audit logs (SP-13: Operator visibility into mutations)
export const handleGetAuditLogs: RequestHandler = async (req: AuthRequest, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit as string, 10) || 50, 100);
    const offset = parseInt(req.query.offset as string, 10) || 0;

    const logs = adminAuditDb.getAll(limit, offset);

    res.json({
      success: true,
      logs,
    });
  } catch (error) {
    console.error('Get audit logs error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch audit logs',
    });
  }
};
