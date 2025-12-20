import 'dotenv/config';
import http from 'node:http';

import app from './app';
import { Logger } from './utils/logger';
import { swaggerDocs } from './config/swagger.config';
import { env } from './config/env.config';

const PORT = env.PORT;

const server = http.createServer(app).listen(PORT, () => {
  Logger.info(`Server is running on port ${PORT}}`);
  swaggerDocs(app, PORT);
});

process.on('unhandledRejection', (err: Error) => {
  Logger.error(
    `UNHANDLED REJECTION! 💥 Shutting down... ${err.name}: ${err.message}`
  );

  server.close(() => {
    process.exit(1);
  });
});

process.on('uncaughtException', (err: Error) => {
  Logger.error(
    `UNCAUGHT EXCEPTION! 💥 Shutting down... ${err.name}: ${err.message}`
  );

  process.exit(1);
});
