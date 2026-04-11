// src/index.js
// ─────────────────────────────────────────────
// Auth Service — Express entry point.
//
// Handles all authentication concerns:
//   - User registration + login
//   - JWT (RS256) issuance and verification
//   - Refresh token rotation (httpOnly cookie)
//   - Redis-backed JWT blacklist for instant logout
//   - Public key endpoint for API Gateway startup
//   - Admin user management
//
// cookie-parser is required to read the httpOnly
// refresh token cookie on POST /auth/refresh.
// ─────────────────────────────────────────────
'use strict';

require('dotenv').config();

const express      = require('express');
const cookieParser = require('cookie-parser');
const { register } = require('prom-client');

const publicKeyRouter = require('./routes/publicKey');
const authRouter      = require('./routes/auth');
const adminRouter     = require('./routes/admin');

const app  = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());

// cookie-parser makes req.cookies available.
// The refresh token arrives as an httpOnly cookie
// — JavaScript cannot read it, only the server can.
app.use(cookieParser());

// ── System endpoints ───────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/metrics', async (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});

// ── Routes ─────────────────────────────────────────────────────────────────
// GET /auth/public-key  — no auth, called by API Gateway at startup
app.use('/auth', publicKeyRouter);

// POST /auth/register, /auth/login, /auth/refresh,
// POST /auth/logout, GET /auth/me, POST /auth/change-password
app.use('/auth', authRouter);

// GET  /auth/admin/users
// PUT  /auth/admin/users/:userId/role
// POST /auth/admin/users/:userId/revoke
app.use('/auth/admin', adminRouter);

// ── Global error handler ───────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error(JSON.stringify({
    event: 'unhandled_error',
    error: err.message,
    path:  req.path,
  }));
  res.status(500).json({ error: 'Internal server error' });
});

// ── Start ──────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(JSON.stringify({ event: 'server_started', port: PORT }));
});
