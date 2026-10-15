import { config } from 'dotenv';
import { defineConfig } from 'prisma/config';

// One source of truth for database settings: the repo-root .env,
// which docker compose also reads.
config({ path: '../.env', quiet: true });

export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: {
    path: 'prisma/migrations',
  },
  datasource: {
    url: process.env['DATABASE_URL'],
  },
});
