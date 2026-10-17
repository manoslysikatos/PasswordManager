import { Controller, Get } from '@nestjs/common';
import { AppService, type Health } from './app.service.js';
import { Public } from './common/auth.decorators.js';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Public()
  @Get('health')
  getHealth(): Promise<Health> {
    return this.appService.getHealth();
  }
}
