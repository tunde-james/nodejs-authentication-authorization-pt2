import { Request, Response, NextFunction } from 'express';

import { AppError } from '../utils/app-error';
import { HttpStatus } from '../config/http-status.config';
import { verifyAccessToken } from '../lib/token';
import { JwtAccessPayload } from '../@types/jwt.types';
import { Role } from '../generated/prisma/enums';
import { prisma } from '../lib/prisma';

export const requireAuth = async (
  req: Request,
  _res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    return next(new AppError('Not authenticated', HttpStatus.UNAUTHORIZED));
  }

  const token = authHeader.split(' ')[1];

  try {
    const payload = verifyAccessToken(token) as JwtAccessPayload;

    const user = await prisma.user.findUnique({
      where: { id: payload.sub },
      select: { tokenVersion: true },
    });

    if (!user || user.tokenVersion !== payload.tokenVersion) {
      return next(
        new AppError('Invalid or expired token', HttpStatus.UNAUTHORIZED)
      );
    }

    req.user = payload;
    next();
  } catch (error) {
    next(new AppError('Invalid or expired token', HttpStatus.UNAUTHORIZED));
  }
};

export const requireROle = (roles: Role[]) => {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (!req.user) {
      return next(new AppError('Not authenticated', HttpStatus.UNAUTHORIZED));
    }

    if (!roles.includes(req.user.role)) {
      return next(
        new AppError(
          'You do not have permission to access this resource',
          HttpStatus.FORBIDDEN
        )
      );
    }

    next();
  };
};
