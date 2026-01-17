import { Request, Response } from 'express';

import { AdminService } from './admin.service';
import { HttpStatus } from '../config/http-status.config';
import { AppError } from '../utils/app-error';

const adminService = new AdminService();

export const getAllUsers = async (req: Request, res: Response) => {
  const users = await adminService.getAllUsers();

  res.status(HttpStatus.OK).json({
    status: 'success',
    results: users.length,
    data: users,
  });
};

export const getUserById = async (req: Request, res: Response) => {
  const { id } = req.params;

  if (!id) {
    throw new AppError('User ID is required', HttpStatus.BAD_REQUEST);
  }

  const user = await adminService.getUserById(id);

  res.status(HttpStatus.OK).json({
    status: 'success',
    data: user,
  });
};

export const unlockUserAccount = async (req: Request, res: Response) => {
  const { id } = req.params;

  if (!id) {
    throw new AppError('User ID is required', HttpStatus.BAD_REQUEST);
  }

  const user = await adminService.unlockUserAccount(id);

  res.status(HttpStatus.OK).json({
    status: 'success',
    message: `Account unlocked for ${user.email}`,
    data: user,
  });
};
