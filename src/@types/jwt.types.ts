import { Role } from '../generated/prisma/enums';

export interface JwtAccessPayload {
  sub: string;
  role: Role;
  tokenVersion: number;
  type: 'access';
  iat: number;
  exp: number;
}

export interface JwtRefreshPayload {
  sub: string;
  tokenVersion: number;
  type: 'refresh';
  jti: string;
  iat: number;
  exp: number;
}
