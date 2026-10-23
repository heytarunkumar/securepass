import 'dotenv/config';
import bcrypt from 'bcryptjs';
import { userDb } from './database';
import { passwordPolicyRegex } from './validation';

async function bootstrapAdmin() {
  const email = process.env.ADMIN_BOOTSTRAP_EMAIL || process.argv[2];
  const password = process.env.ADMIN_BOOTSTRAP_PASSWORD || process.argv[3];
  const force = process.argv.includes('--force');

  console.log('🔒 SecurePass Administrator Bootstrap Utility (SP-01)');

  if (!email || !password) {
    console.error('❌ Error: Both email and password must be provided.');
    console.log('Usage:');
    console.log('  Option 1 (Env vars): ADMIN_BOOTSTRAP_EMAIL=admin@example.com ADMIN_BOOTSTRAP_PASSWORD=<strong_password> npm run bootstrap:admin');
    console.log('  Option 2 (CLI args): npm run bootstrap:admin -- admin@example.com <strong_password>');
    process.exit(1);
  }

  const normalizedEmail = email.toLowerCase().trim();

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(normalizedEmail)) {
    console.error('❌ Error: Invalid email format.');
    process.exit(1);
  }

  // Enforce strong password requirements for administrator accounts
  if (password.length < 12) {
    console.error('❌ Error: Administrator password must be at least 12 characters long.');
    process.exit(1);
  }

  if (
    !passwordPolicyRegex.uppercase.test(password) ||
    !passwordPolicyRegex.lowercase.test(password) ||
    !passwordPolicyRegex.number.test(password) ||
    !passwordPolicyRegex.specialChar.test(password)
  ) {
    console.error('❌ Error: Administrator password must include uppercase, lowercase, numbers, and special characters.');
    process.exit(1);
  }

  // Check if active admins already exist
  const existingAdminCount = userDb.countActiveAdmins();
  if (existingAdminCount > 0 && !force) {
    console.warn(`⚠️ An active administrator account already exists (${existingAdminCount} found).`);
    console.warn('Bootstrap is disabled by default to prevent accidental overwrite. To force creation, re-run with --force.');
    process.exit(0);
  }

  const existingUser = userDb.findAnyByEmail(normalizedEmail);
  if (existingUser) {
    if (!force) {
      console.error(`❌ Error: An account with email ${normalizedEmail} already exists. Use --force to update role/password.`);
      process.exit(1);
    }
  }

  const hashedPassword = bcrypt.hashSync(password, 12);

  if (existingUser) {
    userDb.updateStatus(existingUser.id, true);
    // Update password hash and role
    const db = (await import('./database')).default;
    db.prepare("UPDATE users SET password_hash = ?, role = 'admin', is_active = 1 WHERE id = ?").run(hashedPassword, existingUser.id);
    console.log(`✅ Administrator account updated for ${normalizedEmail}.`);
  } else {
    userDb.create(normalizedEmail, hashedPassword, 'admin');
    console.log(`✅ Administrator account created successfully for ${normalizedEmail}.`);
  }

  console.log('ℹ️ Credentials configured securely. No credentials have been stored in logs.');
  process.exit(0);
}

bootstrapAdmin().catch((err) => {
  console.error('❌ Bootstrap failed:', err);
  process.exit(1);
});
