import { Module } from '@nestjs/common';
import { KeysModule } from '../keys/keys.module.js';
import { VaultsController } from './vaults.controller.js';
import { VaultsService } from './vaults.service.js';

@Module({
  imports: [KeysModule],
  controllers: [VaultsController],
  providers: [VaultsService],
})
export class VaultsModule {}
