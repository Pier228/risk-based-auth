import { Global, Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

@Global() // This module global-scoped
@Module({
  providers: [PrismaService],
  exports: [PrismaService], // Available PrismaService in the whole app
})
export class PrismaDatabaseModule {}
