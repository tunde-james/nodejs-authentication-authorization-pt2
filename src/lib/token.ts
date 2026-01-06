import jwt from 'jsonwebtoken';
import crypto, { randomUUID } from 'node:crypto';

import { env } from '../config/env.config';
import { Role } from '../generated/prisma/enums';
import { prisma } from './prisma';

export const createAccessToken = (
  userId: string,
  role: string,
  tokenVersion: number
) => {
  return jwt.sign(
    { sub: userId, role, tokenVersion, type: 'access' },
    env.JWT_ACCESS_SECRET,
    { expiresIn: '15m' }
  );
};

export const createRefreshToken = (userId: string, tokenVersion: number) => {
  const jti = randomUUID();

  return jwt.sign(
    { sub: userId, tokenVersion, type: 'refresh', jti },
    env.JWT_REFRESH_SECRET,
    { expiresIn: '1d' }
  );
};

export const createEmailVerificationToken = async (
  userId: string,
  email: string
) => {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
  await prisma.emailVerificationToken.create({
    data: { token, userId, email, expiresAt },
  });

  return token;
};

export const createPasswordResetToken = (userId: string, email: string) => {
  return jwt.sign(
    { sub: userId, email, type: 'password_reset' },
    env.JWT_ACCESS_SECRET,
    { expiresIn: '1h' }
  );
};

export const verifyAccessToken = (token: string) => {
  return jwt.verify(token, env.JWT_ACCESS_SECRET) as {
    sub: string;
    role: Role;
    tokenVersion: number;
    type: 'access';
  };
};

export const verifyRefreshToken = (token: string) => {
  return jwt.verify(token, env.JWT_REFRESH_SECRET) as {
    sub: string;
    tokenVersion: number;
    jti: string;
    exp: number;
    type: 'refresh';
  };
};

export const verifyEmailVerificationToken = async (token: string) => {
  const verification = await prisma.emailVerificationToken.findUnique({
    where: { token },
    include: { user: { select: { email: true } } },
  });

  if (
    !verification ||
    verification.used ||
    verification.expiresAt < new Date()
  ) {
    throw new Error('Invalid or expired token');
  }

  return { sub: verification.userId, email: verification.email };
};

export const markEmailVerificationTokenUsed = async (token: string) => {
  await prisma.emailVerificationToken.update({
    where: { token },
    data: { used: true },
  });
};

export const verifyPasswordResetToken = (token: string) => {
  const payload = jwt.verify(token, env.JWT_ACCESS_SECRET) as {
    sub: string;
    email: string;
    type: string;
  };

  if (payload.type !== 'password_reset') {
    throw new Error('Invalid token type');
  }

  return payload;
};
