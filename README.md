# PasswordManager

An enterprise password manager with role-based access control and zero-knowledge encryption. The server stores only ciphertext, and all encryption and decryption happens in the browser.

> Work in progress. Built as an undergraduate thesis project.

## Stack

- **Backend:** NestJS (TypeScript), Prisma, PostgreSQL
- **Frontend:** React + TypeScript (Vite) _(planned)_
- **Crypto (client-side):** Web Crypto API (AES-GCM, RSA-OAEP, HKDF) and Argon2id via `hash-wasm`
- **Auth:** JWT in httpOnly cookies, TOTP MFA

## Getting started

Requirements: Node.js 22+, npm 11+, Docker.

### Database

PostgreSQL 17 runs in Docker. It listens on localhost only.

```bash
cp .env.example .env        # then set your own POSTGRES_PASSWORD (and DATABASE_URL)
docker compose up -d        # start; data is kept in the "pgdata" volume
docker compose stop         # stop (data is kept)
```

### Backend

```bash
cd backend
npm install           # also generates the Prisma client
npm run db:deploy     # create the tables (database must be running)
npm run start:dev     # http://localhost:3000/health -> {"status":"ok","database":"up"}
npm test              # unit tests
npm run test:e2e      # end-to-end tests (use the real database)
```

The backend reads its settings from the repo-root `.env`.
