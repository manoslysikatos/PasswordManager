import { testDatabaseUrl } from './test-db.js';

// Runs in every test worker before the tests: point the app at the test database.
// Environment variables take precedence over the .env file in ConfigModule.
process.env['DATABASE_URL'] = testDatabaseUrl();
