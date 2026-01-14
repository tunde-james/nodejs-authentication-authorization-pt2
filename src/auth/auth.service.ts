import { JsonWebTokenError, TokenExpiredError } from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import crypto from 'node:crypto';

import { HttpStatus } from '../config/http-status.config';
import { prisma } from '../lib/prisma';
import {
  createAccessToken,
  createEmailVerificationToken,
  createRefreshToken,
  markEmailVerificationTokenUsed,
  verifyEmailVerificationToken,
  verifyRefreshToken,
} from '../lib/token';
import { AppError } from '../utils/app-error';
import { Role } from '../generated/prisma/enums';
import { env } from '../config/env.config';
import { sendEmail } from '../config/email';
import { LoginDto } from './auth.schema';
import { DeviceInfo } from '../@types/device-info.types';
import {
  comparePassword,
  getDummyHash,
  hashedPassword,
} from '../lib/password-hash';

const WELCOME_MESSAGES: Record<Role, string> = {
  USER: 'Welcome to our platform!',
  ADMIN: 'Welcome, Admin!',
  DRIVER: 'Welcome, Driver!',
  RESTAURANT_OWNER: 'Welcome, Restaurant Owner',
};

const GENERIC_LOGIN_ERROR = 'Invalid email or password';
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000;

const getGoogleClient = (redirectUri: string) => {
  const clientId = env.GOOGLE_CLIENT_ID;
  const clientSecret = env.GOOGLE_CLIENT_SECRET;

  if (!clientId || !clientSecret || !redirectUri) {
    throw new AppError(
      'Missing Google OAuth env vars',
      HttpStatus.INTERNAL_SERVER_ERROR
    );
  }

  return new OAuth2Client(clientId, clientSecret, redirectUri);
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
      name || ''
    }`;

    await sendEmail(
      email,
      'Verify Your Email',
      `
        <h2>${welcomeMessage}</h2>
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
        throw new AppError('Token expired', HttpStatus.BAD_REQUEST);
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

    await this.sendVerificationEmail(user.id, user.email, user.name, user.role);
  }

  async login(loginDto: LoginDto, deviceInfo: DeviceInfo) {
    const { email, password, twoFactorCode } = loginDto;
    const normalizedEmail = email.toLowerCase().trim();

    return prisma.$transaction(async (tx) => {
      const user = await tx.user.findUnique({
        where: { email: normalizedEmail },
      });

      if (!user) {
        await comparePassword(await getDummyHash(), password);
        throw new AppError(GENERIC_LOGIN_ERROR, HttpStatus.UNAUTHORIZED);
      }

      if (user.lockedUntil && user.lockedUntil > new Date()) {
        const remainingMinutes =
          Math.ceil(user.lockedUntil.getTime() - Date.now()) / 60000;
        throw new AppError(
          `Account is locked. Try again in ${remainingMinutes} minutes(s).`,
          HttpStatus.TOO_MANY_REQUEST
        );
      }

      const isValid = await comparePassword(user.passwordHash, password);
      if (!isValid) {
        const newFailedAttempts = user.failedLoginAttempts + 1;
        const shouldLock = newFailedAttempts >= MAX_FAILED_ATTEMPTS;

        await tx.user.update({
          where: { id: user.id },
          data: {
            failedLoginAttempts: newFailedAttempts,
            lockedUntil: shouldLock
              ? new Date(Date.now() + LOCKOUT_DURATION_MS)
              : null,
          },
        });

        throw new AppError(GENERIC_LOGIN_ERROR, HttpStatus.UNAUTHORIZED);
      }

      if (!user.isEmailVerified) {
        throw new AppError(GENERIC_LOGIN_ERROR, HttpStatus.UNAUTHORIZED);
      }

      await tx.user.update({
        where: { id: user.id },
        data: { failedLoginAttempts: 0, lockedUntil: null },
      });

      await tx.loginHistory.create({
        data: {
          userId: user.id,
          ipAddress: deviceInfo.ipAddress,
          userAgent: deviceInfo.userAgent,
          device: deviceInfo.device,
          os: deviceInfo.os,
          browser: deviceInfo.browser,
          country: deviceInfo.country,
          city: deviceInfo.city,
        },
      });

      const accessToken = createAccessToken(
        user.id,
        user.role,
        user.tokenVersion
      );

      const refreshToken = createRefreshToken(user.id, user.tokenVersion);

      return {
        accessToken,
        refreshToken,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
        },
      };
    });
  }

  async refreshToken(token: string) {
    try {
      const payload = verifyRefreshToken(token);

      return await prisma.$transaction(async (tx) => {
        const blacklisted = await tx.tokenBlacklist.findUnique({
          where: { jti: payload.jti },
        });
        if (blacklisted) {
          throw new AppError('Token already used', HttpStatus.UNAUTHORIZED);
        }

        const user = await tx.user.findUnique({
          where: { id: payload.sub },
          select: { id: true, role: true, tokenVersion: true },
        });

        if (!user || user.tokenVersion !== payload.tokenVersion) {
          throw new AppError('Invalid token', HttpStatus.UNAUTHORIZED);
        }

        await tx.tokenBlacklist.create({
          data: {
            jti: payload.jti,
            expiresAt: new Date(payload.exp * 1000),
          },
        });

        const newAccessToken = createAccessToken(
          user.id,
          user.role,
          user.tokenVersion
        );
        const newRefreshToken = createRefreshToken(user.id, user.tokenVersion);

        return {
          accessToken: newAccessToken,
          refreshToken: newRefreshToken,
        };
      });
    } catch (error) {
      if (error instanceof AppError) throw error;
      throw new AppError('Invalid or expired token', HttpStatus.UNAUTHORIZED);
    }
  }

  async logout(token: string) {
    try {
      const payload = verifyRefreshToken(token);

      const user = await prisma.user.findUnique({
        where: { id: payload.sub },
      });
      if (!user || user.tokenVersion !== payload.tokenVersion) {
        throw new AppError('Invalid token', HttpStatus.UNAUTHORIZED);
      }

      await prisma.tokenBlacklist.create({
        data: {
          jti: payload.jti,
          expiresAt: new Date(payload.exp * 1000),
        },
      });
    } catch (error) {
      if (env.NODE_ENV === 'development') {
        console.error('Logout error (non-critical):', error);
      }
    }
  }

  async getAuthStart(redirectUri: string) {
    const client = getGoogleClient(redirectUri);

    const url = client.generateAuthUrl({
      access_type: 'offline',
      prompt: 'consent',
      scope: ['openid', 'email', 'profile'],
    });

    return url;
  }

  async googleLogin(code: string, deviceInfo: DeviceInfo, redirectUri: string) {
    const client = getGoogleClient(redirectUri);

    const { tokens } = await client.getToken(code);
    if (!tokens.id_token) {
      throw new AppError('No ID token from Google', HttpStatus.BAD_REQUEST);
    }

    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();

    if (!payload || !payload.email || !payload.email_verified) {
      throw new AppError(
        'Invalid or unverified Google email',
        HttpStatus.BAD_REQUEST
      );
    }

    const normalizedEmail = payload.email.toLowerCase().trim();

    return prisma.$transaction(async (tx) => {
      let user = await tx.user.findUnique({
        where: { email: normalizedEmail },
      });

      if (!user) {
        const randomPassword = crypto.randomBytes(32).toString('hex');
        const passwordHash = await hashedPassword(randomPassword);

        user = await tx.user.create({
          data: {
            email: normalizedEmail,
            name: payload.name || 'Unnamed User',
            passwordHash,
            isEmailVerified: true,
            role: 'USER',
            registrationHistory: {
              create: {
                ipAddress: deviceInfo.ipAddress,
                userAgent: deviceInfo.userAgent,
                device: deviceInfo.device,
                os: deviceInfo.os,
                browser: deviceInfo.browser,
                country: deviceInfo.country,
                city: deviceInfo.city,
              },
            },
          },
        });
      } else if (!user.isEmailVerified) {
        await tx.user.update({
          where: { id: user.id },
          data: { isEmailVerified: true },
        });
      }

      await tx.loginHistory.create({
        data: {
          userId: user.id,
          ipAddress: deviceInfo.ipAddress,
          userAgent: deviceInfo.userAgent,
          device: deviceInfo.device,
          os: deviceInfo.os,
          browser: deviceInfo.browser,
          country: deviceInfo.country,
          city: deviceInfo.city,
        },
      });

      const accessToken = createAccessToken(
        user.id,
        user.role,
        user.tokenVersion
      );
      const refreshToken = createRefreshToken(user.id, user.tokenVersion);

      return {
        accessToken,
        refreshToken,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
        },
      };
    });
  }
}
