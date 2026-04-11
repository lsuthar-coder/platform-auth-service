// src/tokens/refresh.js
// ─────────────────────────────────────────────
// Refresh token management.
//
// A refresh token is a 64-byte random hex string.
// It is NOT a JWT.
//
// Storage:
//   Raw token  → httpOnly cookie (client's browser)
//   SHA-256 hash → refresh_tokens table (PostgreSQL)
//
// Why store the hash instead of the raw token?
//   If the database is leaked, the attacker has only
//   SHA-256 hashes. Reversing SHA-256 is computationally
//   infeasible — the raw tokens cannot be used.
//   This is the same defence-in-depth principle used for
//   storing passwords with bcrypt.
//
// Rotation:
//   Each refresh token is one-use. On every successful
//   POST /auth/refresh:
//     1. Old token is marked revoked=true
//     2. A new token is generated and sent as a new cookie
//   If a stolen refresh token is used by an attacker,
//   the legitimate user's next refresh will fail because
//   their token was already rotated — alerting them that
//   something is wrong.
// ─────────────────────────────────────────────
'use strict';

const crypto = require('node:crypto');
const db     = require('../db/postgres');

const REFRESH_TOKEN_BYTES   = 64;
const REFRESH_TOKEN_DAYS    = 7;
const REFRESH_TOKEN_SECONDS = REFRESH_TOKEN_DAYS * 24 * 60 * 60;

/**
 * Generate a new refresh token for a user.
 * Inserts the SHA-256 hash into refresh_tokens table.
 * Returns the raw token to be set as an httpOnly cookie.
 *
 * @param {string} userId
 * @returns {string} raw refresh token (hex string)
 */
async function generateRefreshToken(userId) {
  const rawToken   = crypto.randomBytes(REFRESH_TOKEN_BYTES).toString('hex');
  const tokenHash  = sha256(rawToken);
  const expiresAt  = new Date(Date.now() + REFRESH_TOKEN_SECONDS * 1000);

  await db.query(
    `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
     VALUES ($1, $2, $3)`,
    [userId, tokenHash, expiresAt]
  );

  // Return the RAW token — only this function ever sees it.
  // It goes directly into the httpOnly cookie, never logged.
  return rawToken;
}

/**
 * Validate a refresh token cookie value and rotate it.
 * Returns the userId if valid, throws if invalid or revoked.
 *
 * Rotation means:
 *   1. Mark the presented token as revoked
 *   2. Generate and return a new token for the same user
 *
 * @param {string} cookieValue - raw refresh token from the httpOnly cookie
 * @returns {{ userId: string, newRawToken: string }}
 */
async function rotateRefreshToken(cookieValue) {
  const tokenHash = sha256(cookieValue);

  // Look up the hashed token
  const result = await db.query(
    `SELECT * FROM refresh_tokens
     WHERE token_hash = $1
       AND revoked    = false
       AND expires_at > NOW()`,
    [tokenHash]
  );

  if (!result.rows.length) {
    throw new Error('Invalid or expired refresh token');
  }

  const row = result.rows[0];

  // Revoke the used token (one-use enforcement)
  await db.query(
    'UPDATE refresh_tokens SET revoked = true WHERE id = $1',
    [row.id]
  );

  // Generate a new token for the same user
  const newRawToken = await generateRefreshToken(row.user_id);

  return { userId: row.user_id, newRawToken };
}

/**
 * Revoke ALL refresh tokens for a user.
 * Called on logout and on change-password.
 * Forces re-login on every device.
 */
async function revokeAllTokens(userId) {
  await db.query(
    'UPDATE refresh_tokens SET revoked = true WHERE user_id = $1',
    [userId]
  );
}

/**
 * Build the cookie options for the refresh token.
 * httpOnly: JS cannot read it (XSS protection).
 * Secure:   only sent over HTTPS.
 * SameSite: prevents CSRF attacks.
 */
function cookieOptions() {
  return {
    httpOnly:  true,
    secure:    process.env.NODE_ENV === 'production',
    sameSite:  'strict',
    maxAge:    REFRESH_TOKEN_SECONDS * 1000, // milliseconds
    path:      '/auth',  // only sent to /auth/* endpoints
  };
}

// SHA-256 hash a string — returns hex digest
function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

module.exports = {
  generateRefreshToken,
  rotateRefreshToken,
  revokeAllTokens,
  cookieOptions,
};
