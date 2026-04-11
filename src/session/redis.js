// src/session/redis.js
// ─────────────────────────────────────────────
// Redis session tracking and JWT blacklist.
//
// Two key namespaces:
//
//   session:{userId}
//     Value: "1"
//     TTL:   86400 (24 hours), refreshed on each token refresh
//     Purpose: track that a user has an active session.
//              Used to count active users in Grafana dashboards.
//              Deleted on logout.
//
//   blacklist:{jti}
//     Value: "1"
//     TTL:   remaining seconds until access token expires
//     Purpose: immediately invalidate a specific JWT.
//              The API Gateway checks this on every request.
//              If the key exists → 401 Token Revoked.
//              TTL ensures auto-cleanup when the token
//              would have expired anyway.
// ─────────────────────────────────────────────
'use strict';

const redis = require('../db/redis');

const SESSION_TTL = 86_400; // 24 hours in seconds

/**
 * Create or refresh a session entry for a user.
 * Called on login and on successful token refresh.
 */
async function setSession(userId) {
  await redis.setex(`session:${userId}`, SESSION_TTL, '1');
}

/**
 * Delete the session entry on logout.
 */
async function deleteSession(userId) {
  await redis.del(`session:${userId}`);
}

/**
 * Add a JWT to the blacklist so it is rejected on next use.
 * TTL is set to the token's remaining lifetime so the key
 * auto-cleans when the token would have expired anyway.
 *
 * @param {string} jti         — the jti claim from the JWT payload
 * @param {number} expTimestamp — the exp claim (Unix timestamp in seconds)
 */
async function blacklistToken(jti, expTimestamp) {
  const remainingSeconds = expTimestamp - Math.floor(Date.now() / 1000);

  if (remainingSeconds <= 0) {
    // Token already expired — no need to blacklist
    return;
  }

  await redis.setex(`blacklist:${jti}`, remainingSeconds, '1');
}

/**
 * Check if a JTI is blacklisted.
 * Returns true if the token has been revoked.
 * (The API Gateway also checks this independently — this is
 * for any direct calls to Auth Service endpoints.)
 */
async function isBlacklisted(jti) {
  const result = await redis.exists(`blacklist:${jti}`);
  return result === 1;
}

module.exports = { setSession, deleteSession, blacklistToken, isBlacklisted };
