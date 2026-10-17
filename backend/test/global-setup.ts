import { execSync } from 'node:child_process';
import { join } from 'node:path';
import pg from 'pg';
import { testDatabaseUrl } from './test-db.js';

// Runs once before the e2e suite: creates the test database if needed and applies all migrations.
export default async function setup(): Promise<void> {
  const testUrl = new URL(testDatabaseUrl());
  const testDb = testUrl.pathname.slice(1);

  const adminUrl = new URL(testUrl);
  adminUrl.pathname = '/postgres';
  const client = new pg.Client({ connectionString: adminUrl.toString() });
  await client.connect();
  const exists = await client.query('SELECT 1 FROM pg_database WHERE datname = $1', [testDb]);
  if (exists.rowCount === 0) await client.query(`CREATE DATABASE "${testDb}"`);
  await client.end();

  execSync('npx prisma migrate deploy', {
    cwd: join(import.meta.dirname, '..'),
    env: { ...process.env, DATABASE_URL: testUrl.toString() },
    stdio: 'pipe',
  });
}
