import { Request, Response } from 'express';

import { AuthService } from './auth.service';
import { AppError } from '../utils/app-error';
import { HttpStatus } from '../config/http-status.config';
import { handleVerificationResponse } from '../lib/email-verification-response';

const authService = new AuthService();

export const verifyEmail = async (req: Request, res: Response) => {
  const { token } = req.query;

  if (!token || typeof token !== 'string') {
    return handleVerificationResponse(res, false, 'Invalid or missing token');
  }

  try {
    await authService.verifyEmail(token);

    return handleVerificationResponse(
      res,
      true,
      'Email verified successfully. You can now log in.'
    );
  } catch (error) {
    const message =
      error instanceof AppError
        ? error.message
        : 'Verification failed. Please try again';

    return handleVerificationResponse(res, false, message);
  }
};

export const resendVerificationEmail = async (req: Request, res: Response) => {
  const { email } = req.body;

  if (!email || typeof email !== 'string') {
    throw new AppError('Email is required', HttpStatus.BAD_REQUEST);
  }

  await authService.resendVerificationEmail(email);

  res.status(HttpStatus.OK).json({
    status: 'success',
    message: 'Verification email sent. Please check your inbox.',
  });
};
