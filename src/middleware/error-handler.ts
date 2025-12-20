import { Request, Response, NextFunction, ErrorRequestHandler } from 'express';
import { JsonWebTokenError, TokenExpiredError } from 'jsonwebtoken';

import { Logger } from '../utils/logger';
import { AppError } from '../utils/app-error';
import { z, ZodError } from 'zod';
import { HttpStatus } from '../config/http-status.config';
import { ErrorCodeEnum } from '../enums/error-code.enum';
import { env } from '../config/env.config';

const isProduction = env.NODE_ENV === 'production';

const GENERIC_AUTH_ERROR = 'Authentication failed';

const formatZodError = (res: Response, error: z.ZodError) => {
  const errors = error?.issues?.map((err) => ({
    field: err.path.join('.'),
    message: err.message,
  }));

  return res.status(HttpStatus.BAD_REQUEST).json({
    status: 'fail',
    message: 'Validation failed',
    errors: errors,
    errorCode: ErrorCodeEnum.VALIDATION_ERROR,
  });
};

export const errorHandler: ErrorRequestHandler = (
  err: Error,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  let error = { ...err };
  error.message = err.message;

  if (!isProduction) {
    Logger.info(
      `${err.name} - ${err.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`
    );
  } else {
    Logger.error(
      `${err.name} - ${err.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`
    );
  }

  if (err instanceof AppError) {
    return res.status(err.statusCode).json({
      message: err.message,
      errorCode: err.errorCode,
    });
  }

  if (err instanceof ZodError) {
    return formatZodError(res, err);
  }

  if (err instanceof JsonWebTokenError) {
    return res.status(HttpStatus.UNAUTHORIZED).json({
      status: 'fail',
      errorCode: ErrorCodeEnum.AUTH_SESSION_INVALID,
      message: isProduction ? GENERIC_AUTH_ERROR : err.message,
    });
  }

  if (err instanceof TokenExpiredError) {
    return res.status(HttpStatus.UNAUTHORIZED).json({
      status: 'fail',
      errorCode: ErrorCodeEnum.AUTH_SESSION_EXPIRED,
      message: isProduction ? GENERIC_AUTH_ERROR : err.message,
    });
  }

  return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
    status: 'error',
    message: 'Internal Server Error',
    ...(isProduction ? {} : { err: err?.message || 'Unknown error occurred' }),
  });
};
