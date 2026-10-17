import type { CookieOptions, Response } from 'express';

export const ACCESS_COOKIE = 'pm_access';
export const REFRESH_COOKIE = 'pm_refresh';
export const ACCESS_TTL_SECONDS = 15 * 60;
export const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;

// httpOnly: page JavaScript cannot read the tokens (XSS cannot steal them).
// sameSite strict: other sites cannot make the browser send them (CSRF).
// secure: HTTPS only in production; local development runs on plain http.
function baseOptions(): CookieOptions {
  return { httpOnly: true, sameSite: 'strict', secure: process.env['NODE_ENV'] === 'production' };
}

export function setAuthCookies(res: Response, accessToken: string, refreshToken: string): void {
  res.cookie(ACCESS_COOKIE, accessToken, { ...baseOptions(), path: '/', maxAge: ACCESS_TTL_SECONDS * 1000 });
  // The refresh token is only ever sent to /auth (refresh, logout), not with every API call.
  res.cookie(REFRESH_COOKIE, refreshToken, { ...baseOptions(), path: '/auth', maxAge: REFRESH_TTL_MS });
}

export function clearAuthCookies(res: Response): void {
  res.clearCookie(ACCESS_COOKIE, { ...baseOptions(), path: '/' });
  res.clearCookie(REFRESH_COOKIE, { ...baseOptions(), path: '/auth' });
}
