import { Request, Response } from 'express';

import { registerDriverSchema, registerSchema } from './user.schema';
import { extractDeviceInfo, getClientIp } from '../lib/device-info';
import { UserService } from './user.service';
import { HttpStatus } from '../config/http-status.config';

const userService = new UserService();

export const register = async (req: Request, res: Response) => {
  const data = registerSchema.parse(req.body);
  const ip = getClientIp(req);
  const userAgent = req.headers['user-agent'] || 'Unknown';
  const deviceInfo = extractDeviceInfo(ip, userAgent);

  const user = await userService.createUser(data, deviceInfo);

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

  res.status(HttpStatus.CREATED).json({
    status: 'success',
    message:
      'Driver registration successful. Please check your email to verify your account.',
  });
};
