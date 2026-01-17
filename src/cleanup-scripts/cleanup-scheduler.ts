import cron from 'node-cron';
import type { ScheduledTask } from 'node-cron';

import { env } from '../config/env.config';
import { Logger } from '../utils/logger';
import { cleanupLoginHistory } from './cleanup-login-history';
import { cleanupExpiredTokens } from './cleanup-tokens';
import { CleanupSummary } from './types/cleanup.types';
import { prisma } from '../lib/prisma';

export const runAllCleanups = async (): Promise<CleanupSummary> => {
  const startTime = Date.now();
  const results = [];

  if (env.CLEANUP_TOKEN_ENABLED) {
    try {
      const tokenResult = await cleanupExpiredTokens();
      results.push(tokenResult);
    } catch (error) {
      Logger.error(`Token cleanup failed during scheduled run: ${error}`);
    }
  }

  if (env.CLEANUP_LOGIN_HISTORY_ENABLED) {
    try {
      const loginResult = await cleanupLoginHistory();
      results.push(loginResult);
    } catch (error) {
      Logger.error(
        `Login history cleanup failed during scheduled run: ${error}`,
      );
    }
  }

  const summary: CleanupSummary = {
    results,
    totalDeleted: results.reduce((sum, r) => sum + r.deletedCount, 0),
    executionTimeMs: Date.now() - startTime,
    completedAt: new Date(),
  };

  Logger.info(
    `Scheduled cleanup completed: ${summary.totalDeleted} total entries deleted in ${summary.executionTimeMs}ms`,
  );

  return summary;
};

export const startCleanupScheduler = (): ScheduledTask => {
  const schedule = env.CLEANUP_CRON_SCHEDULE;

  if (!cron.validate(schedule)) {
    Logger.error(`Invalid cron expression: ${schedule}`);
    throw new Error(`Invalid cron expression: ${schedule}`);
  }

  Logger.info(`Starting cleanup scheduler with schedule: ${schedule}`);

  const task = cron.schedule(
    schedule,
    async () => {
      Logger.info('Cleanup scheduler triggered');
      await runAllCleanups();
    },
    {
      timezone: 'UTC',
    },
  );

  const humanReadableSchedule = getHumanReadableSchedule(schedule);

  Logger.info(`Cleanup scheduler started. Schedule: ${humanReadableSchedule}`);

  return task;
};

function getHumanReadableSchedule(cronExpr: string): string {
  const scheduleMap: Record<string, string> = {
    '0 3 * * *': 'Daily at 3:00 AM UTC',
    '0 0 * * *': 'Daily at midnight UTC',
    '0 * * * *': 'Every hour',
    '*/5 * * * *': 'Every 5 minutes',
    '0 0 * * 0': 'Weekly on Sunday at midnight UTC',
  };

  return scheduleMap[cronExpr] || `Cron: ${cronExpr}`;
}

export const stopCleanupScheduler = (task: ScheduledTask): void => {
  task.stop();
  Logger.info('Cleanup scheduler stopped');
};

if (require.main === module) {
  const task = startCleanupScheduler();

  const shutdown = async () => {
    Logger.info('Shutting down cleanup scheduler...');

    stopCleanupScheduler(task);

    await prisma.$disconnect();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  Logger.info('Cleanup scheduler running. Press Ctrl+C to stop.');
}
