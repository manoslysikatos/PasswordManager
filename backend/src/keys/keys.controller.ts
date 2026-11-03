import { Body, Controller, Get, Post } from '@nestjs/common';
import { type AuthUser, CurrentUser } from '../common/auth.decorators.js';
import { FulfilKeysDto } from './dto.js';
import { KeysService } from './keys.service.js';

// Open to every signed-in user: the answer only lists what that user's browser is able to lock,
// so for most people it is empty.
@Controller('keys/pending')
export class KeysController {
  constructor(private readonly keys: KeysService) {}

  @Get()
  pending(@CurrentUser() user: AuthUser) {
    return this.keys.pending(user);
  }

  @Post()
  fulfil(@Body() dto: FulfilKeysDto, @CurrentUser() user: AuthUser) {
    return this.keys.fulfil(dto, user);
  }
}
