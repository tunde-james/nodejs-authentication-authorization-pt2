import { env } from '../config/env.config';
import { prisma } from '../lib/prisma';
import { Logger } from '../utils/logger';
import { CleanupResult } from './types/cleanup.types';

export async function cleanupLoginHistory(): Promise<CleanupResult> {
  const retentionDays = env.LOGIN_HISTORY_RETENTION_DAYS;
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

  try {
    const oldEntriesCount = await prisma.loginHistory.count({
      where: {
        loginTime: {
          lt: cutoffDate,
        },
      },
    });

    if (oldEntriesCount === 0) {
      Logger.info(
        `Login history cleanup: No entries older than ${retentionDays} days to delete`,
      );
      return {
        deletedCount: 0,
        timestamp: new Date(),
        type: 'login_history',
      };
    }

    const result = await prisma.loginHistory.deleteMany({
      where: {
        loginTime: {
          lt: cutoffDate,
        },
      },
    });

    const cleanupResult: CleanupResult = {
      deletedCount: result.count,
      timestamp: new Date(),
      type: 'login_history',
    };

    Logger.info(
      `Login history cleanup: Deleted ${result.count} entries older than ${retentionDays} days`,
    );
    return cleanupResult;
  } catch (error) {
    Logger.error(`Login history cleanup failed: ${error}`);
    throw error;
  }
}

if (require.main === module) {
  cleanupLoginHistory()
    .then(async (result) => {
      console.log(
        `Cleanup complete. Deleted ${result.deletedCount} login history entries at ${result.timestamp.toISOString()}.`,
      );

      await prisma.$disconnect();
      process.exit(0);
    })
    .catch(async (error) => {
      console.error('Cleanup failed:', error);

      await prisma.$disconnect();
      process.exit(1);
    });
}
