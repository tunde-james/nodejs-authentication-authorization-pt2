import crypto from 'node:crypto';

export const generateBackupCodes = (count = 8): string[] => {
  return Array.from({ length: count }, () =>
    crypto.randomBytes(4).toString('hex').toUpperCase()
  );
};

export const hashBackupCode = (code: string): string => {
  return crypto.createHash('sha256').update(code).digest('hex');
};


