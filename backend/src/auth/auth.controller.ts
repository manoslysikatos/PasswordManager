import { Body, Controller, Get, HttpCode, Param, Post, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import { type AuthUser, CurrentUser, Public, RequirePermission, requestMeta } from '../common/auth.decorators.js';
import { AuthService } from './auth.service.js';
import { REFRESH_COOKIE } from './cookies.js';
import { CreateInvitationDto, LoginDto, PreloginDto, RegisterDto, SetupDto } from './dto.js';
import { InvitationsService } from './invitations.service.js';
import { SetupService } from './setup.service.js';

function refreshCookie(req: Request): string | undefined {
  const value: unknown = req.cookies?.[REFRESH_COOKIE];
  return typeof value === 'string' ? value : undefined;
}

@Controller('setup')
export class SetupController {
  constructor(private readonly setup: SetupService) {}

  @Public()
  @Get('status')
  async status() {
    return { needsSetup: await this.setup.needsSetup() };
  }

  @Public()
  @Post()
  create(@Body() dto: SetupDto) {
    return this.setup.setup(dto);
  }
}

@Controller('invitations')
export class InvitationsController {
  constructor(private readonly invitations: InvitationsService) {}

  @RequirePermission('MANAGE_USERS')
  @Post()
  create(@Body() dto: CreateInvitationDto, @CurrentUser() user: AuthUser) {
    return this.invitations.create(dto, user);
  }

  @Public()
  @Get(':token')
  describe(@Param('token') token: string) {
    return this.invitations.describe(token);
  }
}

@Controller('auth')
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly invitations: InvitationsService,
  ) {}

  @Public()
  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.invitations.accept(dto);
  }

  @Public()
  @HttpCode(200)
  @Post('prelogin')
  prelogin(@Body() dto: PreloginDto) {
    return this.auth.prelogin(dto.email);
  }

  @Public()
  @HttpCode(200)
  @Post('login')
  login(@Body() dto: LoginDto, @Req() req: Request, @Res({ passthrough: true }) res: Response) {
    return this.auth.login(dto, requestMeta(req), res);
  }

  @Public()
  @HttpCode(204)
  @Post('refresh')
  refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    return this.auth.refresh(refreshCookie(req), res);
  }

  @Public()
  @HttpCode(204)
  @Post('logout')
  logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    return this.auth.logout(refreshCookie(req), res);
  }

  @Get('me')
  me(@CurrentUser() user: AuthUser) {
    return this.auth.me(user);
  }
}
