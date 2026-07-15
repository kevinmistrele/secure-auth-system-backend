import {
  ArgumentsHost,
  Catch,
  ConflictException,
  ExceptionFilter,
  NotFoundException,
} from '@nestjs/common';
import { BaseExceptionFilter } from '@nestjs/core';
import { Prisma } from '@prisma/client';

/**
 * Maps known Prisma errors to HTTP errors without leaking internals:
 * P2002 (unique violation) -> 409, P2025 (record not found) -> 404.
 * "Not found" is also what a cross-tenant probe sees — RLS filters the row
 * out, so an unauthorized caller cannot learn the resource exists.
 */
@Catch(Prisma.PrismaClientKnownRequestError)
export class PrismaExceptionFilter
  extends BaseExceptionFilter
  implements ExceptionFilter
{
  catch(
    exception: Prisma.PrismaClientKnownRequestError,
    host: ArgumentsHost,
  ): void {
    if (exception.code === 'P2002') {
      return super.catch(new ConflictException('Resource already exists'), host);
    }
    if (exception.code === 'P2025') {
      return super.catch(new NotFoundException('Resource not found'), host);
    }
    super.catch(exception, host);
  }
}
