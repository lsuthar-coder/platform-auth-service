// src/routes/publicKey.js
// ─────────────────────────────────────────────
// GET /auth/public-key
//
// Returns the RSA public key PEM so the API Gateway can
// fetch it at startup for local JWT verification.
//
// NO authentication required — public keys are designed
// to be public. Anyone can use this key to verify tokens
// but they cannot use it to create new tokens (that
// requires the private key, which never leaves this service).
//
// The API Gateway calls this once at startup:
//   const { publicKey } = await fetch('http://auth-service:5000/auth/public-key')
//   → caches in memory → verifies all subsequent JWTs locally
//
// When the OCI Function rotates the key pair, restarting
// the API Gateway pods triggers a fresh fetch of this endpoint.
// ─────────────────────────────────────────────
'use strict';

const express          = require('express');
const router           = express.Router();
const { getPublicKeyPem } = require('../tokens/jwt');

router.get('/public-key', async (req, res) => {
  try {
    const publicKey = await getPublicKeyPem();
    res.json({ publicKey });
  } catch (err) {
    console.error(JSON.stringify({ event: 'public_key_error', error: err.message }));
    res.status(500).json({ error: 'Public key not available' });
  }
});

module.exports = router;
