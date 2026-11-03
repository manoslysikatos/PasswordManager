import { randomBytes } from 'node:crypto';
import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module.js';
import { configureApp } from '../src/app.setup.js';

// A fresh app per file, so the in-memory counters start at zero. Unknown emails and tokens are
// enough here: the limits count every attempt, whatever its outcome.
describe('Rate limiting (e2e)', () => {
  let app: INestApplication<App>;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication();
    configureApp(app);
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  const http = () => request(app.getHttpServer());
  const verifier = () => randomBytes(32).toString('base64');

  it('allows 10 login attempts per account, then answers 429 with Retry-After', async () => {
    for (let i = 0; i < 10; i++) {
      await http().post('/auth/login').send({ email: 'target@example.com', authVerifier: verifier() }).expect(401);
    }
    // Case and spaces don't buy extra attempts.
    const blocked = await http().post('/auth/login').send({ email: ' Target@Example.com', authVerifier: verifier() }).expect(429);
    expect(blocked.body.message).toBe('Too many attempts, try again later');
    expect(Number(blocked.get('Retry-After'))).toBeGreaterThan(0);
  });

  it('does not block other accounts behind the same IP', async () => {
    await http().post('/auth/login').send({ email: 'colleague@example.com', authVerifier: verifier() }).expect(401);
  });

  it('limits prelogin to 20 per account', async () => {
    for (let i = 0; i < 20; i++) {
      await http().post('/auth/prelogin').send({ email: 'probe@example.com' }).expect(200);
    }
    await http().post('/auth/prelogin').send({ email: 'probe@example.com' }).expect(429);
  });

  it('limits registration attempts per IP', async () => {
    for (let i = 0; i < 10; i++) {
      await http().post('/auth/register').send({}).expect(400);
    }
    await http().post('/auth/register').send({}).expect(429);
  });

  it('leaves endpoints without @RateLimit alone', async () => {
    for (let i = 0; i < 15; i++) {
      await http().get('/health').expect(200);
    }
  });
});
