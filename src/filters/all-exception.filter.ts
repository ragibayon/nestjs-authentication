import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpStatus,
} from '@nestjs/common';

import { Response } from 'express';

@Catch()
export class AllExceptionFilter implements ExceptionFilter {
  catch(exception: any, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();

    let errorResponse = {
      message: exception.message,
      error: exception.error,
      statusCode: exception.status || HttpStatus.INTERNAL_SERVER_ERROR,
      timeStamp: new Date().toISOString(),
    };

    if (exception.name === 'MongoServerError' && exception.code === 11000) {
      errorResponse.message = `Duplicate key entered for ${Object.keys(
        exception.keyValue,
      )}`;
      errorResponse.error = exception.name;
      errorResponse.statusCode = HttpStatus.CONFLICT;
    }

    response.status(errorResponse.statusCode).json(errorResponse);
  }
}
