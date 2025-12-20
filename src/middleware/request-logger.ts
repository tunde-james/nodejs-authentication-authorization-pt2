import morgan from 'morgan';

import { Logger } from '../utils/logger';

const stream = {
  write: (message: string) => Logger.http(message.trim()),
};

const skip = () => {
  const env = process.env.NODE_ENV || 'development';
  return env !== 'development';
};

export const morganMiddleware = morgan(
  ':method :url :status :res[content-length] - :response-time ms :remote-addr',
  { stream, skip }
);
