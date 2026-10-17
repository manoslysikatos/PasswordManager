import { join } from 'node:path';
import { config } from 'dotenv';

/** e2e tests use their own database (<name>_test) so they never touch development data. */
export function testDatabaseUrl(): string {
  config({ path: join(import.meta.dirname, '..', '..', '.env'), quiet: true });
  const url = new URL(process.env['DATABASE_URL'] ?? '');
  if (!url.pathname.endsWith('_test')) url.pathname = `${url.pathname}_test`;
  return url.toString();
}

export const APP_TABLES = [
  'audit_log',
  'rotation_tasks',
  'credential_shares',
  'credentials',
  'vault_keys',
  'vault_role_grants',
  'vaults',
  'org_key_grants',
  'organization',
  'role_permissions',
  'user_roles',
  'roles',
  'refresh_tokens',
  'invitations',
  'users',
];
