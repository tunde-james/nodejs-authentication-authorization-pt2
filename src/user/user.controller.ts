import { Request, Response } from 'express';

import {
  registerDriverSchema,
  registerRestaurantSchema,
  registerSchema,
} from './user.schema';
import { extractDeviceInfo, getClientIp } from '../lib/device-info';
import { UserService } from './user.service';
import { HttpStatus } from '../config/http-status.config';
import { AuthService } from '../auth/auth.service';

const userService = new UserService();
const authService = new AuthService();

export const register = async (req: Request, res: Response) => {
  const data = registerSchema.parse(req.body);
  const ip = getClientIp(req);
  const userAgent = req.headers['user-agent'] || 'Unknown';
  const deviceInfo = extractDeviceInfo(ip, userAgent);

  const user = await userService.createUser(data, deviceInfo);

  await authService
    .sendVerificationEmail(user.id, user.email, data.name, user.role)
    .catch((err) => {
      console.error('Failed to send verification email:', err);
    });

  res.status(HttpStatus.CREATED).json({
    status: 'success',
    message:
      'Registration successful. Please check your email to verify your account',
  });
};

export const registerDriver = async (req: Request, res: Response) => {
  const data = registerDriverSchema.parse(req.body);
  const ip = getClientIp(req);
  const userAgent = req.headers['user-agent'] || 'Unknown';
  const deviceInfo = extractDeviceInfo(ip, userAgent);

  const user = await userService.createDriver(data, deviceInfo);

  await authService
    .sendVerificationEmail(
      user.id,
      user.email,
      data.name,
      user.role
    )
    .catch((err) => {
      console.error('Failed to send verification email:', err);
    });

  res.status(HttpStatus.CREATED).json({
    status: 'success',
    message:
      'Driver registration successful. Please check your email to verify your account.',
  });
};

export const registerRestaurant = async (req: Request, res: Response) => {
  const data = registerRestaurantSchema.parse(req.body);
  const ip = getClientIp(req);
  const userAgent = req.headers['user-agent'] || 'Unknown';
  const deviceInfo = extractDeviceInfo(ip, userAgent);

  const user = await userService.createRestaurant(data, deviceInfo);

  await authService.sendVerificationEmail(
    user.id,
    user.email,
    data.name,
    user.role
  );

  res.status(HttpStatus.CREATED).json({
    status: 'success',
    message:
      'Restaurant registration successful. Please check your email to verify your account.',
  });
};
