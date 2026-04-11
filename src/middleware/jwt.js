// src/middleware/jwt.js
// ─────────────────────────────────────────────
// Middleware for protecting routes that require an
// authenticated user (Bearer token in Authorization header).
//
// Used on:
//   POST /auth/logout
//   GET  /auth/me
//   POST /auth/change-password
//   All /auth/admin/* routes
// ─────────────────────────────────────────────
'use strict';

const { verifyAccessToken } = require('../tokens/jwt');
const { isBlacklisted }     = require('../session/redis');

/**
 * Verify Bearer token and attach req.user.
 * Returns 401 if missing, invalid, expired, or blacklisted.
 */
async function requireAuth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authorization required' });
  }

  const token = header.split(' ')[1];

  try {
    const payload = await verifyAccessToken(token);

    // Check blacklist (covers logout case)
    if (await isBlacklisted(payload.jti)) {
      return res.status(401).json({ error: 'Token revoked' });
    }

    req.user = payload; // { sub, email, role, jti, iat, exp }
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

/**
 * Same as requireAuth but also requires role === 'admin'.
 * Used on all /auth/admin/* routes.
 */
async function requireAdmin(req, res, next) {
  await requireAuth(req, res, () => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  });
}

module.exports = { requireAuth, requireAdmin };
