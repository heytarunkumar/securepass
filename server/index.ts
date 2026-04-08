import "dotenv/config";
import express from "express";
import cors from "cors";
import { handleDemo } from "./routes/demo";
import { handlePasswordAnalysis } from "./routes/password-analysis";
import { handleRegister, handleLogin, handleProfile, handleLogout } from "./routes/auth";
import {
  handleAdminStats,
  handleGetUsers,
  handleUpdateUserStatus,
  handleDeleteUser,
  handleGetUserDetails
} from "./routes/admin";
import { authenticateToken, requireAdmin, optionalAuth } from "./auth";
import "./database"; // Initialize database

export function createServer() {
  const app = express();

  // Middleware
  app.use(cors());
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Example API routes
  app.get("/api/ping", (_req, res) => {
    const ping = process.env.PING_MESSAGE ?? "ping";
    res.json({ message: ping });
  });

  app.get("/api/demo", handleDemo);

  // Password analysis (with optional auth for logging)
  app.post("/api/password-analysis", optionalAuth, handlePasswordAnalysis);

  // Authentication routes
  app.post("/api/auth/register", handleRegister);
  app.post("/api/auth/login", handleLogin);
  app.get("/api/auth/profile", authenticateToken, handleProfile);
  app.post("/api/auth/logout", authenticateToken, handleLogout);

  // Admin routes
  app.get("/api/admin/stats", authenticateToken, requireAdmin, handleAdminStats);
  app.get("/api/admin/users", authenticateToken, requireAdmin, handleGetUsers);
  app.get("/api/admin/users/:userId", authenticateToken, requireAdmin, handleGetUserDetails);
  app.patch("/api/admin/users/:userId/status", authenticateToken, requireAdmin, handleUpdateUserStatus);
  app.delete("/api/admin/users/:userId", authenticateToken, requireAdmin, handleDeleteUser);

  return app;
}
