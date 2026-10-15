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

```bash
cd backend
npm install
npm run build
npm test
```

Database setup with Docker Compose will be added next.
