import { Request } from 'express';

import { JwtAccessPayload } from './jwt.types';

declare module 'express' {
  interface Request {
    requestId?: string;
    user?: JwtAccessPayload;
  }
}
