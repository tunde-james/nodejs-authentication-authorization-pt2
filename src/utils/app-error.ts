import { HttpStatus, HttpStatusCodeType } from '../config/http-status.config';
import { ErrorCodeEnum, ErrorCodeEnumType } from '../enums/error-code.enum';

export class AppError extends Error {
  public statusCode: HttpStatusCodeType;
  public errorCode?: ErrorCodeEnumType;
  public isOperational: boolean;

  constructor(
    message: string,
    statusCode = HttpStatus.INTERNAL_SERVER_ERROR,
    errorCode?: ErrorCodeEnumType
  ) {
    super(message);

    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

export class HttpException extends AppError {
  constructor(
    message = 'Http Exception Error',
    statusCode: HttpStatusCodeType,
    errorCode?: ErrorCodeEnumType
  ) {
    super(message, statusCode, errorCode);
  }
}

export class NotFoundException extends AppError {
  constructor(message = 'Resource not found', errorCode?: ErrorCodeEnumType) {
    super(
      message,
      HttpStatus.NOT_FOUND,
      errorCode || ErrorCodeEnum.RESOURCE_NOT_FOUND
    );
  }
}

export class BadRequestException extends AppError {
  constructor(message = 'Bad Reques', errorCode?: ErrorCodeEnumType) {
    super(
      message,
      HttpStatus.BAD_REQUEST,
      errorCode || ErrorCodeEnum.VALIDATION_ERROR
    );
  }
}

export class UnauthorizedException extends AppError {
  constructor(message = 'Unauthorized Access', errorCode?: ErrorCodeEnumType) {
    super(
      message,
      HttpStatus.UNAUTHORIZED,
      errorCode || ErrorCodeEnum.ACCESS_UNAUTHORIZED
    );
  }
}

export class ConflictException extends AppError {
  constructor(message = 'Conflict', errorCode?: ErrorCodeEnumType) {
    super(
      message,
      HttpStatus.CONFLICT,
      errorCode || ErrorCodeEnum.INTERNAL_SERVER_ERROR
    );
  }
}

export class InternalServerException extends AppError {
  constructor(
    message = 'Internal Server Error',
    errorCode?: ErrorCodeEnumType
  ) {
    super(
      message,
      HttpStatus.INTERNAL_SERVER_ERROR,
      errorCode || ErrorCodeEnum.INTERNAL_SERVER_ERROR
    );
  }
}
