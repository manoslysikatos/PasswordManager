import { Controller, Get } from '@nestjs/common';
import { AppService, type Health } from './app.service.js';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get('health')
  getHealth(): Promise<Health> {
    return this.appService.getHealth();
  }
}
