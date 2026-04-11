// src/metrics.js
// Prometheus metrics for the Auth Service.
'use strict';

const client = require('prom-client');

client.collectDefaultMetrics({ prefix: 'auth_service_node_' });

// Counter: login attempts broken down by result
// Labels: result = 'success' | 'failed' | 'register'
const logins = new client.Counter({
  name:       'auth_logins_total',
  help:       'Total login attempts by result',
  labelNames: ['result'],
});

// Gauge: number of registered users (updated on registration)
const userCount = new client.Gauge({
  name: 'auth_user_count',
  help: 'Total number of registered users',
});

module.exports = { logins, userCount };
