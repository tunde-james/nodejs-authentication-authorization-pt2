import { prisma } from '../lib/prisma';
import { Logger } from '../utils/logger';
import { CleanupResult } from './types/cleanup.types';

export const cleanupExpiredTokens = async (): Promise<CleanupResult> => {
  try {
    const expiredCount = await prisma.tokenBlacklist.count({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    });

    if (expiredCount === 0) {
      Logger.info('Token blacklist cleanup: No expired tokens to delete');

      return {
        deletedCount: 0,
        timestamp: new Date(),
        type: 'token_blacklist',
      };
    }

    const result = await prisma.tokenBlacklist.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    });

    const cleanupResult: CleanupResult = {
      deletedCount: result.count,
      timestamp: new Date(),
      type: 'token_blacklist',
    };

    Logger.info(
      `Token blacklist cleanup: Deleted ${result.count} expires entries`,
    );

    return cleanupResult;
  } catch (error) {
    Logger.error(`Token blacklist cleanup failed: ${error}`);
    throw error;
  }
};

if (require.main === module) {
  cleanupExpiredTokens()
    .then(async (result) => {
      console.log(
        `Cleanup complete. Deleted ${result.deletedCount} expired tokens at ${result.timestamp.toISOString()}`,
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
