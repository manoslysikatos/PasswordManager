import { type INestApplication, ValidationPipe } from '@nestjs/common';
import cookieParser from 'cookie-parser';

/** Shared by main.ts and the e2e tests, so tests run the app exactly as in production. */
export function configureApp(app: INestApplication): void {
  app.use(cookieParser());
  // Rejects requests with unknown fields or wrong types before they reach a controller.
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
}
