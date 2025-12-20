import express, { Express } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';

import { morganMiddleware } from './middleware/request-logger';
import { errorHandler } from './middleware/error-handler';
import { env } from './config/env.config';

const app: Express = express();

app.use(helmet());

app.use(
  cors({
    origin: env.APP_URL,
    credentials: true,
  })
);

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

app.use(morganMiddleware);

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Server is running' });
});

app.use(errorHandler);

export default app;
