// src/routes/admin.js
// ─────────────────────────────────────────────
// Admin user management routes.
// All require role === 'admin' in the JWT (enforced by requireAdmin).
//
// GET  /auth/admin/users                  list all users
// PUT  /auth/admin/users/:userId/role     change role
// POST /auth/admin/users/:userId/revoke   revoke all sessions
// ─────────────────────────────────────────────
'use strict';

const express  = require('express');
const router   = express.Router();
const db       = require('../db/postgres');
const { revokeAllTokens }    = require('../tokens/refresh');
const { deleteSession }      = require('../session/redis');
const { requireAdmin }       = require('../middleware/jwt');

// Apply admin check to ALL routes in this router
router.use(requireAdmin);

// ── GET /auth/admin/users ──────────────────────────────────────────────────
// List all user accounts. Password hash is never returned.
router.get('/users', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT id, email, role, created_at, last_login
       FROM users
       ORDER BY created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /auth/admin/users/:userId/role ─────────────────────────────────────
// Change a user's role between 'user' and 'admin'.
// The updated role takes effect on the user's NEXT login or
// token refresh (existing JWTs contain the old role until expiry).
router.put('/users/:userId/role', async (req, res) => {
  const { role } = req.body;

  if (!['user', 'admin'].includes(role)) {
    return res.status(400).json({ error: "role must be 'user' or 'admin'" });
  }

  // Prevent admin from removing their own admin role
  if (req.params.userId === req.user.sub && role !== 'admin') {
    return res.status(400).json({ error: 'Cannot remove your own admin role' });
  }

  try {
    const result = await db.query(
      'UPDATE users SET role = $1 WHERE id = $2 RETURNING id, email, role',
      [role, req.params.userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /auth/admin/users/:userId/revoke ──────────────────────────────────
// Revoke all active sessions for a user.
// Forces re-login on all their devices.
// Note: their current access tokens remain valid until expiry (max 15min).
// To immediately invalidate access tokens you would need their JTIs —
// this endpoint just prevents new access tokens from being issued
// via refresh.
router.post('/users/:userId/revoke', async (req, res) => {
  try {
    const result = await db.query(
      'SELECT id, email FROM users WHERE id = $1',
      [req.params.userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });

    // Revoke all refresh tokens
    await revokeAllTokens(req.params.userId);

    // Delete their session from Redis
    await deleteSession(req.params.userId);

    res.json({
      message: `All sessions revoked for ${result.rows[0].email}`,
      userId:  req.params.userId,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
