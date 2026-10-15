import { join } from 'node:path';
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller.js';
import { AppService } from './app.service.js';
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
    PrismaModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
