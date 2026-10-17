import { join } from 'node:path';
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import { AppController } from './app.controller.js';
import { AppService } from './app.service.js';
import { AuditModule } from './audit/audit.module.js';
import { AuthGuard } from './auth/auth.guard.js';
import { AuthModule } from './auth/auth.module.js';
import { ACCESS_TTL_SECONDS } from './auth/cookies.js';
import { validateEnv } from './config/env.validation.js';
import { PrismaModule } from './prisma/prisma.module.js';

@Module({
  imports: [
    // The repo-root .env (shared with docker compose). Resolves the same from src/ and dist/.
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: join(import.meta.dirname, '..', '..', '.env'),
      validate: validateEnv,
    }),
    JwtModule.registerAsync({
      global: true,
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.getOrThrow<string>('JWT_SECRET'),
        signOptions: { expiresIn: ACCESS_TTL_SECONDS },
      }),
    }),
    PrismaModule,
    AuditModule,
    AuthModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    // Every endpoint requires a session unless marked @Public().
    { provide: APP_GUARD, useClass: AuthGuard },
  ],
})
export class AppModule {}
