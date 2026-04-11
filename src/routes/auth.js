// src/routes/auth.js
// ─────────────────────────────────────────────
// Core authentication routes.
//
// POST /auth/register       — create account
// POST /auth/login          — issue access token + refresh cookie
// POST /auth/refresh        — rotate refresh token → new access token
// POST /auth/logout         — blacklist JWT + revoke refresh tokens
// GET  /auth/me             — current user profile (requires Bearer)
// POST /auth/change-password — update password (requires Bearer)
// ─────────────────────────────────────────────
'use strict';

const express  = require('express');
const router   = express.Router();
const crypto   = require('node:crypto');
const db       = require('../db/postgres');
const { signAccessToken }                        = require('../tokens/jwt');
const { generateRefreshToken, rotateRefreshToken,
        revokeAllTokens, cookieOptions }          = require('../tokens/refresh');
const { setSession, deleteSession, blacklistToken } = require('../session/redis');
const { requireAuth }                            = require('../middleware/jwt');
const metrics                                    = require('../metrics');

// ── POST /auth/register ────────────────────────────────────────────────────
// Create a new user account. Hashes password with bcrypt-equivalent
// using Node's built-in crypto.scrypt (no external dependency needed).
// For a production system use bcrypt (npm i bcrypt) with cost factor 12.
router.post('/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  // Basic email format check
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  try { 
    // Hash password using scrypt (memory-hard, resistant to GPU cracking)
    // Salt is generated fresh for each password
    const salt         = crypto.randomBytes(16).toString('hex');
    const derivedKey   = await scryptHash(password, salt);
    const passwordHash = `${salt}:${derivedKey}`;

    const result = await db.query(
      `INSERT INTO users (email, password_hash)
       VALUES (LOWER($1), $2) RETURNING id, email, role, created_at`,
      [email, passwordHash]
    );

    metrics.logins.inc({ result: 'register' }); 
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Email already registered' });
    }
    res.status(500).json({ error: err.message });
  }
});

// ── POST /auth/login ───────────────────────────────────────────────────────
// Verify credentials, issue access token + set refresh token cookie.
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  try {
    // Look up user by email (case-insensitive)
    const result = await db.query(
      'SELECT * FROM users WHERE email = LOWER($1)', [email]
    );

    if (!result.rows.length) {
      // Return same error for unknown email as wrong password
      // Prevents user enumeration attacks
      metrics.logins.inc({ result: 'failed' });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // Verify password against stored hash
    const [salt, storedKey] = user.password_hash.split(':');
    const derivedKey        = await scryptHash(password, salt);

    // Timing-safe comparison prevents timing attacks
    const valid = crypto.timingSafeEqual(
      Buffer.from(derivedKey,  'hex'),
      Buffer.from(storedKey,   'hex')
    );

    if (!valid) {
      metrics.logins.inc({ result: 'failed' });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Issue access token (JWT, 15 minutes)
    const { token, jti, expiresIn } = await signAccessToken(user);

    // Generate refresh token and store its SHA-256 hash in DB
    // The raw token goes into the httpOnly cookie — never in the response body
    const rawRefreshToken = await generateRefreshToken(user.id);

    // Track active session in Redis
    await setSession(user.id);

    // Update last_login timestamp
    await db.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);

    // Set httpOnly cookie — JavaScript CANNOT read this
    // Only the browser sends it automatically to /auth/* routes
    res.cookie('refreshToken', rawRefreshToken, cookieOptions());

    metrics.logins.inc({ result: 'success' });
    res.json({ accessToken: token, expiresIn });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /auth/refresh ─────────────────────────────────────────────────────
// Rotate the refresh token and issue a new access token.
// No request body needed — the browser sends the httpOnly cookie automatically.
router.post('/refresh', async (req, res) => {
  const cookieValue = req.cookies?.refreshToken;

  if (!cookieValue) {
    return res.status(401).json({ error: 'Refresh token not found' });
  }

  try {
    // rotateRefreshToken: validates hash in DB, revokes old token,
    // creates and returns a new token
    const { userId, newRawToken } = await rotateRefreshToken(cookieValue);

    // Fetch user for the new access token payload
    const result = await db.query(
      'SELECT id, email, role FROM users WHERE id = $1', [userId]
    );
    if (!result.rows.length) {
      return res.status(401).json({ error: 'User not found' });
    }
    const user = result.rows[0];

    // Issue new access token
    const { token, expiresIn } = await signAccessToken(user);

    // Refresh the session TTL in Redis
    await setSession(userId);

    // Set new refresh token cookie (old one is now invalid)
    res.cookie('refreshToken', newRawToken, cookieOptions());

    res.json({ accessToken: token, expiresIn });
  } catch (err) {
    // Invalid / expired / revoked cookie
    res.clearCookie('refreshToken', { path: '/auth' });
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// ── POST /auth/logout ──────────────────────────────────────────────────────
// Blacklist the current access token + revoke all refresh tokens.
// The access token is rejected on the next request to the API Gateway.
router.post('/logout', requireAuth, async (req, res) => {
  try {
    const { sub: userId, jti, exp } = req.user;

    // Add this specific JWT to Redis blacklist.
    // TTL = remaining lifetime so key auto-cleans when token expires.
    await blacklistToken(jti, exp);

    // Revoke ALL refresh tokens for this user (logout from all devices)
    await revokeAllTokens(userId);

    // Delete the session entry
    await deleteSession(userId);

    // Clear the refresh token cookie
    res.clearCookie('refreshToken', { path: '/auth' });

    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /auth/me ───────────────────────────────────────────────────────────
// Return the current user's profile from the database.
// The JWT payload already has email + role, but this also
// returns last_login and created_at from PostgreSQL.
router.get('/me', requireAuth, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT id, email, role, created_at, last_login FROM users WHERE id = $1',
      [req.user.sub]
    );
    if (!result.rows.length) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /auth/change-password ─────────────────────────────────────────────
// Update password after verifying the current one.
// Revokes all sessions — forces re-login on every device.
router.post('/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'currentPassword and newPassword are required' });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  }

  try {
    const result = await db.query(
      'SELECT * FROM users WHERE id = $1', [req.user.sub]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    const user = result.rows[0];

    // Verify current password
    const [salt, storedKey] = user.password_hash.split(':');
    const derivedKey        = await scryptHash(currentPassword, salt);
    const valid = crypto.timingSafeEqual(
      Buffer.from(derivedKey, 'hex'),
      Buffer.from(storedKey,  'hex')
    );

    if (!valid) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Hash the new password
    const newSalt    = crypto.randomBytes(16).toString('hex');
    const newKey     = await scryptHash(newPassword, newSalt);
    const newHash    = `${newSalt}:${newKey}`;

    await db.query(
      'UPDATE users SET password_hash = $1 WHERE id = $2',
      [newHash, user.id]
    );

    // Revoke all refresh tokens — force re-login everywhere
    await revokeAllTokens(user.id);
    await deleteSession(user.id);
    res.clearCookie('refreshToken', { path: '/auth' });

    res.json({ message: 'Password updated. Please log in again.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Helper: scrypt password hash ───────────────────────────────────────────
// Uses Node's built-in crypto.scrypt — no external dependency.
// Wrapped in a promise for async/await usage.
// N=16384, r=8, p=1 matches bcrypt cost-12 in computational cost.
function scryptHash(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, key) => {
      if (err) reject(err);
      else resolve(key.toString('hex'));
    });
  });
}

module.exports = router;
