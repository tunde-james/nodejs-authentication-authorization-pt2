import express, { Express } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';

import { morganMiddleware } from './middleware/request-logger';
import { errorHandler } from './middleware/error-handler';
import { env } from './config/env.config';
import { requestIdMiddleware } from './middleware/request-id.middleware';
import userRoutes from './routes/v1/user.routes';
import authRoutes from './routes/v1/auth.routes';
import adminRoutes from './routes/v1/admin.routes';
import { startCleanupScheduler } from './cleanup-scripts/cleanup-scheduler';
import { Logger } from './utils/logger';

const app: Express = express();

app.set('trust proxy', 1);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  }),
);

app.use(
  cors({
    origin: env.APP_URL,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
  }),
);

app.use(cookieParser());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

app.use(requestIdMiddleware);

app.use(morganMiddleware);

app.use('/api/v1/users', userRoutes);
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/admin', adminRoutes);

app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    message: 'Server is running',
    timestamp: new Date().toISOString(),
  });
});

app.use(errorHandler);

if (env.NODE_ENV === 'production') {
  try {
    startCleanupScheduler();
  } catch (error) {
    Logger.error(`Failed to start cleanup scheduler: ${error}`);
  }
}

export default app;
