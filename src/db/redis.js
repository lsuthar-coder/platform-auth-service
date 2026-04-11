// src/db/redis.js
// ─────────────────────────────────────────────
// Shared Redis client.
// Auth Service uses Redis for two key namespaces:
//   session:{userId}   — active session tracking (TTL 86400)
//   blacklist:{jti}    — revoked JWT IDs (TTL = remaining token lifetime)
//
// The API Gateway reads the blacklist namespace.
// The Auth Service writes to both.
// ─────────────────────────────────────────────
'use strict';

const Redis = require('ioredis');

const redis = new Redis(process.env.REDIS_URL || 'redis://redis-master:6379', {
  maxRetriesPerRequest: 3,
  retryStrategy: (times) => Math.min(times * 50, 2_000),
});

redis.on('error',   (err) => console.error(JSON.stringify({ event: 'redis_error',     error: err.message })));
redis.on('connect', ()    => console.log  (JSON.stringify({ event: 'redis_connected' })));

module.exports = redis;
