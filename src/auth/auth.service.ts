import { JsonWebTokenError, TokenExpiredError } from 'jsonwebtoken';

import { HttpStatus } from '../config/http-status.config';
import { prisma } from '../lib/prisma';
import {
  createEmailVerificationToken,
  markEmailVerificationTokenUsed,
  verifyEmailVerificationToken,
} from '../lib/token';
import { AppError } from '../utils/app-error';
import { Role } from '../generated/prisma/enums';
import { env } from '../config/env.config';
import { sendEmail } from '../config/email';

const WELCOME_MESSAGES: Record<Role, string> = {
  USER: 'Welcome to our platform!',
  ADMIN: 'Welcome, Admin!',
  DRIVER: 'Welcome, Driver!',
  RESTAURANT_OWNER: 'Welcome, Restaurant Owner',
};

export class AuthService {
  sendVerificationEmail = async (
    userId: string,
    email: string,
    name: string,
    role: Role
  ): Promise<void> => {
    const verifyToken = await createEmailVerificationToken(userId, email);
    const verifyUrl = `${env.APP_URL}/api/v1/auth/verify-email?token=${verifyToken}`;
    const welcomeMessage = `${WELCOME_MESSAGES[role] || 'Welcome!'}, ${
      name ? name : ''
    }`;

    await sendEmail(
      email,
      'Verify Your Email',
      `
        <h2>${welcomeMessage}, ${name}!</h2>
        <p>Thank you for registering. Please verify your email address to complete your registration.</p>
        <p><a href="${verifyUrl}" style="background-color: #4CAF50; color: white; padding: 14px 20px; text-decoration: none; display: inline-block; border-radius: 4px;">Verify Email</a></p>
        <p>Or copy and paste this link in your browser:</p>
        <p>${verifyUrl}</p>
        <p><strong>This link expires in 15 minutes.</strong></p>
        <p>If you didn't create an account, you can safely ignore this email.</p>
      `
    );
  };

  async verifyEmail(token: string): Promise<void> {
    try {
      const payload = await verifyEmailVerificationToken(token);

      const user = await prisma.user.findUnique({
        where: { id: payload.sub },
        select: { id: true, email: true, isEmailVerified: true },
      });

      if (!user) throw new AppError('User not found', HttpStatus.NOT_FOUND);

      if (user.email !== payload.email) {
        throw new AppError('Invalid token', HttpStatus.BAD_REQUEST);
      }

      if (user.isEmailVerified) {
        throw new AppError('Email already verified', HttpStatus.BAD_REQUEST);
      }

      await prisma.user.update({
        where: { id: user.id },
        data: { isEmailVerified: true },
      });

      await markEmailVerificationTokenUsed(token);
    } catch (error) {
      if (error instanceof JsonWebTokenError) {
        throw new AppError('Invalid token', HttpStatus.BAD_REQUEST);
      }

      if (error instanceof TokenExpiredError) {
        throw new AppError('TOken expired', HttpStatus.BAD_REQUEST);
      }

      throw error;
    }
  }

  async resendVerificationEmail(email: string): Promise<void> {
    const normalizedEmail = email.toLowerCase().trim();

    const user = await prisma.user.findUnique({
      where: { email: normalizedEmail },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        isEmailVerified: true,
      },
    });

    if (!user) {
      throw new AppError('User not found', HttpStatus.NOT_FOUND);
    }

    if (user.isEmailVerified) {
      throw new AppError('Email already verified', HttpStatus.BAD_REQUEST);
    }

    await this.sendVerificationEmail(
      user.id,
      user.email,
      user.name || '',
      user.role
    );
  }
}
