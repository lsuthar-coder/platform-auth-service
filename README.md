# Auth Service

JWT authentication service for the lsuthar.in platform. Issues RS256-signed access tokens and refresh tokens, backed by PostgreSQL and Redis.

---

## Features

- **RS256 JWT** — Asymmetric signing with 2048-bit RSA key pair
- **Access + Refresh Tokens** — 15-minute access tokens, 7-day refresh tokens
- **Refresh Token Rotation** — Old token invalidated on each refresh
- **Redis Token Blacklist** — Logout invalidates tokens immediately
- **bcrypt Password Hashing** — Cost factor 12
- **Role-based** — `user` and `admin` roles embedded in JWT claims

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/auth/register` | None | Create account |
| `POST` | `/auth/login` | None | Login, returns tokens |
| `POST` | `/auth/refresh` | Refresh token | Rotate access token |
| `POST` | `/auth/logout` | Bearer | Invalidate token |
| `GET` | `/auth/public-key` | None | RS256 public key (PEM) |
| `GET` | `/auth/me` | Bearer | Current user info |
| `GET` | `/health` | None | Health check |

## JWT Claims

```json
{
  "sub": "uuid",
  "email": "user@lsuthar.in",
  "role": "user",
  "jti": "uuid",
  "iat": 1234567890,
  "exp": 1234568790
}
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_URL` | Redis connection URL |
| `PRIVATE_KEY_PEM` | RSA private key (PEM format) |
| `PUBLIC_KEY_PEM` | RSA public key (PEM format) |
| `PORT` | Server port (default: 5000) |

## Local Development

```bash
npm install
cp .env.example .env
# Generate RSA keys:
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
npm start
```

## Docker

```bash
docker buildx build --platform linux/amd64 -t ghcr.io/lsuthar-coder/auth-service:latest --push .
```

## CI/CD

- **CI** — GitHub Actions: lint, test, Docker build and push to GHCR on every push to `main`
- **CD** — Jenkins: triggered by GitHub Actions after successful CI, deploys to K8s via `kubectl set image`

## Deployment

Deployed on **K3s** (Contabo VPS, `167.86.90.32`) in the `platform` namespace.

Secrets stored in Kubernetes secret `auth-service-secrets`:
- RSA private and public keys
- PostgreSQL connection string
- Redis URL

K8s manifests live in `k8s/`:
```
k8s/
├── deployment.yaml
├── service.yaml
└── ingress.yaml
```

Apply manually:
```bash
kubectl apply -f k8s/
```

## Tech Stack

- Node.js + Express
- jsonwebtoken (RS256)
- bcryptjs
- ioredis
- pg (PostgreSQL)