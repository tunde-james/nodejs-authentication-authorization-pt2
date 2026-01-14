import { Request, Response } from 'express';

import { AuthService } from './auth.service';
import { AppError } from '../utils/app-error';
import { HttpStatus } from '../config/http-status.config';
import { handleVerificationResponse } from '../lib/email-verification-response';
import { loginSchema } from './auth.schema';
import { extractDeviceInfo, getClientIp } from '../lib/device-info';
import { env } from '../config/env.config';

const authService = new AuthService();

const REFRESH_TOKEN_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: env.NODE_ENV === 'production',
  sameSite: 'strict' as const,
  maxAge: 1 * 24 * 60 * 60 * 1000, // 1 day
  path: '/api/v1/auth',
};

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

export const login = async (req: Request, res: Response) => {
  const data = loginSchema.parse(req.body);
  const ip = getClientIp(req);
  const userAgent = req.headers['user-agent'] || 'Unknown';
  const deviceInfo = extractDeviceInfo(ip, userAgent);

  const { accessToken, refreshToken, user } = await authService.login(
    data,
    deviceInfo
  );

  res.cookie('refreshToken', refreshToken, REFRESH_TOKEN_COOKIE_OPTIONS);

  res.status(HttpStatus.OK).json({
    status: 'success',
    accessToken,
    data: { user },
  });
};

export const refreshToken = async (req: Request, res: Response) => {
  const token = req.cookies.refreshToken;
  if (!token) {
    throw new AppError('No refresh token provided', HttpStatus.UNAUTHORIZED);
  }

  const { accessToken, refreshToken: newRefreshToken } =
    await authService.refreshToken(token);

  res.cookie('refreshToken', newRefreshToken, REFRESH_TOKEN_COOKIE_OPTIONS);

  res.status(HttpStatus.OK).json({
    status: 'success',
    accessToken,
  });
};

export const refreshTokenMobile = async (req: Request, res: Response) => {
  const token = req.body.refreshToken;
  if (!token) {
    throw new AppError('No refresh token provided', HttpStatus.UNAUTHORIZED);
  }

  const { accessToken, refreshToken: newAccessToken } =
    await authService.refreshToken(token);

  res.status(HttpStatus.OK).json({
    status: 'success',
    accessToken,
    refreshToken: newAccessToken,
  });
};

export const logout = async (req: Request, res: Response) => {
  const token = req.cookies.refreshToken || req.body.refreshToken;

  if (!token) {
    return res.status(HttpStatus.OK).json({
      status: 'success',
      message: 'Logged out successfully',
    });
  }

  await authService.logout(token);

  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/api/v1/auth',
  });

  res.status(HttpStatus.OK).json({
    status: 'success',
    message: 'Logged out successfully',
  });
};

export const googleAuthStartHandler = async (req: Request, res: Response) => {
  const redirectUri =
    (req.query.redirectUri as string) || env.GOOGLE_REDIRECT_URI;
  const url = await authService.getAuthStart(redirectUri);
  res.redirect(url);
};

export const googleAuthCallbackHandler = async (
  req: Request,
  res: Response
) => {
  const code = req.query.code as string | undefined;
  if (!code) {
    throw new AppError('Missing code in callback', HttpStatus.BAD_REQUEST);
  }

  const redirectUri =
    (req.query.redirectUri as string) || env.GOOGLE_REDIRECT_URI;
  const ip = getClientIp(req);
  const userAgent = req.headers['user-agent'] || 'Unknown';
  const deviceInfo = extractDeviceInfo(ip, userAgent);

  const { accessToken, refreshToken, user } = await authService.googleLogin(
    code,
    deviceInfo,
    redirectUri
  );

  res.cookie('refreshToken', refreshToken, REFRESH_TOKEN_COOKIE_OPTIONS);

  res.status(HttpStatus.OK).json({
    status: 'success',
    accessToken,
    user,
  });
};
