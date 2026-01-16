import { Request, Response } from 'express';

import {
  registerDriverSchema,
  registerRestaurantSchema,
  registerSchema,
  updateProfileSchema,
} from './user.schema';
import { extractDeviceInfo, getClientIp } from '../lib/device-info';
import { UserService } from './user.service';
import { HttpStatus } from '../config/http-status.config';
import { AuthService } from '../auth/auth.service';
import { AppError } from '../utils/app-error';
import { deleteFromCloudinary } from '../middleware/upload.middleware';

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
    .sendVerificationEmail(user.id, user.email, data.name, user.role)
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

export const getMe = async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AppError('Not authenticated', HttpStatus.UNAUTHORIZED);
  }

  const profile = await userService.getProfile(req.user.sub);

  res.status(HttpStatus.OK).json({
    status: 'success',
    data: profile,
  });
};

export const updateMe = async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AppError('Not authenticated', HttpStatus.UNAUTHORIZED);
  }

  const data = updateProfileSchema.parse(req.body);
  const profile = await userService.updateProfile(req.user.sub, data);
  res.status(HttpStatus.OK).json({
    status: 'success',
    data: profile,
  });
};

export const uploadAvatar = async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AppError('Not authenticated', HttpStatus.UNAUTHORIZED);
  }

  if (!req.file) {
    throw new AppError('No file uploaded', HttpStatus.BAD_REQUEST);
  }

  const cloudinaryUrl = req.file.path;
  const publicId = req.file.filename;

  if (!cloudinaryUrl || !publicId) {
    throw new AppError(
      'Upload failed: Missing file information',
      HttpStatus.INTERNAL_SERVER_ERROR
    );
  }

  try {
    const profile = await userService.updateAvatar(
      req.user.sub,
      cloudinaryUrl,
      publicId
    );

    res.status(HttpStatus.OK).json({
      status: 'success',
      data: {
        profilePicture: profile.profilePicture,
        size: req.file.size,
        mimetype: req.file.mimetype,
      },
    });
  } catch (error) {
    console.error('[uploadAvatar] Database update failed, cleaning up:', error);

    await deleteFromCloudinary(publicId).catch((err) => {
      console.error('Failed to cleanup orphaned file:', err);
    });
    
    throw error;
  }
};

export const deleteAvatar = async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AppError('Not authenticated', HttpStatus.UNAUTHORIZED);
  }

  const result = await userService.deleteAvatar(req.user.sub);

  res.status(HttpStatus.OK).json({
    status: 'success',
    message: result.message,
  });
};
