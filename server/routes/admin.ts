import { RequestHandler } from "express";
import { 
  userDb, 
  passwordCheckDb, 
  loginAttemptsDb,
  passwordHistoryDb 
} from "../database";
import { AuthRequest } from "../auth";
import { AdminStats } from "@shared/api";

// Get admin dashboard statistics
export const handleAdminStats: RequestHandler = async (req: AuthRequest, res) => {
  try {
    const totalUsers = userDb.getCount();
    const totalPasswordsChecked = passwordCheckDb.getCount();
    const breachedPasswordsFound = passwordCheckDb.getBreachedCount();
    const averagePasswordStrength = passwordCheckDb.getAverageStrength();
    
    // Get strength distribution
    const strengthDistribution = passwordCheckDb.getStrengthDistribution();
    const distributionMap: AdminStats['strengthDistribution'] = {
      'Very Weak': 0,
      'Weak': 0,
      'Fair': 0,
      'Good': 0,
      'Strong': 0,
      'Very Strong': 0
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
      strengthDistribution: distributionMap
    };

    res.json({
      success: true,
      stats
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch admin statistics'
    });
  }
};

// Get all users
export const handleGetUsers: RequestHandler = async (req: AuthRequest, res) => {
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
        twoFactorEnabled: user.two_factor_enabled === 1,
        passwordCount: passwordHistory.length,
        lastPasswordCheck: passwordHistory[0]?.created_at || null
      };
    });

    res.json({
      success: true,
      users: usersWithStats
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch users'
    });
  }
};

// Update user status (activate/deactivate)
export const handleUpdateUserStatus: RequestHandler = async (req: AuthRequest, res) => {
  try {
    const { userId } = req.params;
    const { isActive } = req.body;

    if (typeof isActive !== 'boolean') {
      return res.status(400).json({
        success: false,
        message: 'isActive must be a boolean value'
      });
    }

    // Don't allow admins to deactivate themselves
    if (userId === req.user?.id && !isActive) {
      return res.status(400).json({
        success: false,
        message: 'You cannot deactivate your own account'
      });
    }

    const user = userDb.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    userDb.updateStatus(userId, isActive);

    res.json({
      success: true,
      message: `User ${isActive ? 'activated' : 'deactivated'} successfully`
    });
  } catch (error) {
    console.error('Update user status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update user status'
    });
  }
};

// Delete user
export const handleDeleteUser: RequestHandler = async (req: AuthRequest, res) => {
  try {
    const { userId } = req.params;

    // Don't allow admins to delete themselves
    if (userId === req.user?.id) {
      return res.status(400).json({
        success: false,
        message: 'You cannot delete your own account'
      });
    }

    const user = userDb.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    userDb.delete(userId);

    res.json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete user'
    });
  }
};

// Get user details
export const handleGetUserDetails: RequestHandler = async (req: AuthRequest, res) => {
  try {
    const { userId } = req.params;

    const user = userDb.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
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
        twoFactorEnabled: user.two_factor_enabled === 1,
        passwordHistory: passwordHistory.map(p => ({
          id: p.id,
          strength: p.strength_level,
          score: p.strength_score,
          entropy: p.entropy,
          isBreached: p.is_breached === 1,
          breachCount: p.breach_count,
          createdAt: p.created_at
        }))
      }
    });
  } catch (error) {
    console.error('Get user details error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch user details'
    });
  }
};

// Get recent password checks
export const handleGetRecentChecks: RequestHandler = async (req: AuthRequest, res) => {
  try {
    const limit = parseInt(req.query.limit as string) || 50;
    
    // This would require a new database query, for now return empty
    res.json({
      success: true,
      checks: []
    });
  } catch (error) {
    console.error('Get recent checks error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch recent checks'
    });
  }
};

// Get breach alerts
export const handleGetBreachAlerts: RequestHandler = async (req: AuthRequest, res) => {
  try {
    // This would require implementing breach alert system
    res.json({
      success: true,
      alerts: []
    });
  } catch (error) {
    console.error('Get breach alerts error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch breach alerts'
    });
  }
};
