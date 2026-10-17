// Fails fast at startup if a required setting is missing or too weak.
const REQUIRED = ['DATABASE_URL', 'JWT_SECRET', 'SERVER_SECRET'] as const;
const SECRETS = ['JWT_SECRET', 'SERVER_SECRET'] as const;
const MIN_SECRET_LENGTH = 32;

export function validateEnv(env: Record<string, unknown>): Record<string, unknown> {
  const missing = REQUIRED.filter((key) => typeof env[key] !== 'string' || env[key] === '');
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')} (see .env.example)`);
  }
  const weak = SECRETS.filter((key) => (env[key] as string).length < MIN_SECRET_LENGTH);
  if (weak.length > 0) {
    throw new Error(`${weak.join(', ')} must be at least ${MIN_SECRET_LENGTH} characters long`);
  }
  return env;
}
