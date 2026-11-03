import { applyDecorators, UseGuards } from '@nestjs/common';
import { minutes, Throttle, ThrottlerGuard, type ThrottlerGetTrackerFunction } from '@nestjs/throttler';

// Rate limits apply only where declared: the public endpoints an attacker can hit without a session.
// Signed-in traffic is not limited, because a whole office often shares one IP address.
// Counters are kept per endpoint, in memory (fine for one server instance).
export const RATE_LIMIT_WINDOW_MS = minutes(15);
export const RATE_LIMIT_MESSAGE = 'Too many attempts, try again later';

// Counted per IP *and* email: colleagues behind the same IP don't use up each other's attempts,
// and a password guesser gets only a few tries per account from each address.
// The guard runs before validation, so the body may be anything.
const byIpAndEmail: ThrottlerGetTrackerFunction = (req) => {
  const email: unknown = req.body?.email;
  return `${req.ip}|${typeof email === 'string' ? email.trim().toLowerCase() : ''}`;
};

/** Allows `limit` requests per 15 minutes; the next ones get 429 with a Retry-After header. */
export function RateLimit(limit: number, per: 'ip' | 'ip+email' = 'ip') {
  return applyDecorators(
    UseGuards(ThrottlerGuard),
    Throttle({ default: { limit, ttl: RATE_LIMIT_WINDOW_MS, ...(per === 'ip+email' && { getTracker: byIpAndEmail }) } }),
  );
}
