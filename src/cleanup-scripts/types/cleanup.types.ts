export interface CleanupResult {
  deletedCount: number;
  timestamp: Date;
  type: 'token_blacklist' | 'login_history';
}

export interface CleanupSummary {
  results: CleanupResult[];
  totalDeleted: number;
  executionTimeMs: number;
  completedAt: Date;
}
