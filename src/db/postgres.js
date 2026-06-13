// src/db/postgres.js
// ─────────────────────────────────────────────
// PostgreSQL pool. Owns: users, refresh_tokens.
// No other service should ever read these tables directly.
// ─────────────────────────────────────────────
'use strict';

const { Pool } = require('pg');

const pool = new Pool({
  connectionString:        process.env.DATABASE_URL,
  max:                     10,
  idleTimeoutMillis:       30_000,
  connectionTimeoutMillis: 5_000,
  ssl: false, // required for OCI ADB
});

pool.on('error', (err) => {
  console.error(JSON.stringify({ event: 'pg_pool_error', error: err.message }));
});

module.exports = pool;
