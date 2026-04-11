// src/tokens/jwt.js
// ─────────────────────────────────────────────
// RS256 JWT signing and verification.
//
// Private key  — signs new access tokens. Lives ONLY in this
//                service via K8s Secret PRIVATE_KEY_PEM env var.
//                Never exposed externally.
//
// Public key   — verifies tokens. Exposed via GET /auth/public-key
//                so the API Gateway can fetch it at startup.
//
// Access token payload:
//   sub   — userId (UUID)
//   email — user's email address
//   role  — 'user' | 'admin'
//   jti   — unique UUID per token (used for Redis blacklist)
//   iat   — issued-at timestamp
//   exp   — expiry timestamp (iat + 15 minutes)
//
// Why RS256 over HS256?
//   HS256 uses one shared secret — any service holding it can
//   forge new tokens. RS256 uses a key pair — only this service
//   can sign tokens (private key), but any service can verify
//   them (public key). Compromise of the Gateway or Flag API
//   cannot produce new valid tokens.
// ─────────────────────────────────────────────
'use strict';

const { SignJWT, jwtVerify, importPKCS8, importSPKI } = require('jose');
const { v4: uuidv4 } = require('uuid');

let privateKey = null;
let publicKey  = null;

// Lazy-load keys from environment on first use.
// Keys are injected from K8s Secret at pod startup.
async function loadKeys() {
  if (privateKey && publicKey) return;

  const privatePem = process.env.PRIVATE_KEY_PEM;
  const publicPem  = process.env.PUBLIC_KEY_PEM;

  if (!privatePem || !publicPem) {
    throw new Error('PRIVATE_KEY_PEM and PUBLIC_KEY_PEM must be set');
  }

  privateKey = await importPKCS8(privatePem, 'RS256');
  publicKey  = await importSPKI(publicPem,  'RS256');
}

/**
 * Sign a new RS256 access token for the given user.
 * Expires in 15 minutes.
 *
 * @param {{ id, email, role }} user
 * @returns {{ token: string, jti: string, expiresIn: number }}
 */
async function signAccessToken(user) {
  await loadKeys();

  const jti = uuidv4(); // unique ID — used for blacklisting on logout

  const token = await new SignJWT({
    email: user.email,
    role:  user.role,
    jti,
  })
    .setProtectedHeader({ alg: 'RS256' })
    .setSubject(user.id)          // sub = userId
    .setIssuedAt()
    .setExpirationTime('15m')
    .sign(privateKey);

  return { token, jti, expiresIn: 900 }; // 900 seconds = 15 minutes
}

/**
 * Verify an RS256 token. Returns the decoded payload.
 * Throws if invalid, expired, or wrong algorithm.
 */
async function verifyAccessToken(token) {
  await loadKeys();
  const { payload } = await jwtVerify(token, publicKey, { algorithms: ['RS256'] });
  return payload;
}

/**
 * Return the public key PEM string.
 * Used by GET /auth/public-key — exposed so the API Gateway
 * can fetch it at startup for local JWT verification.
 */
async function getPublicKeyPem() {
  if (!process.env.PUBLIC_KEY_PEM) {
    throw new Error('PUBLIC_KEY_PEM not set');
  }
  return process.env.PUBLIC_KEY_PEM;
}

module.exports = { signAccessToken, verifyAccessToken, getPublicKeyPem };
