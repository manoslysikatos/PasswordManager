import { Module } from '@nestjs/common';
import { AuthController, InvitationsController, SetupController } from './auth.controller.js';
import { AuthService } from './auth.service.js';
import { InvitationsService } from './invitations.service.js';
import { SetupService } from './setup.service.js';

@Module({
  controllers: [SetupController, InvitationsController, AuthController],
  providers: [AuthService, InvitationsService, SetupService],
})
export class AuthModule {}
