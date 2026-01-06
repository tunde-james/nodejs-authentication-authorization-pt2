import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z
    .enum(['development', 'test', 'production', 'staging'])
    .default('development'),

  PORT: z
    .string()
    .default('5000')
    .transform((val) => parseInt(val, 10)),

  DATABASE_URL: z.url(),

  JWT_ACCESS_SECRET: z.string().min(1),
  JWT_REFRESH_SECRET: z.string().min(1),

  GOOGLE_CLIENT_ID: z.string().min(1),
  GOOGLE_CLIENT_SECRET: z.string().min(1),
  GOOGLE_REDIRECT_URI: z.url(),

  APP_URL: z.url(),

  FRONTEND_URL: z.url().optional(),

  SMTP_HOST: z.string().min(1),
  SMTP_PORT: z.string().transform((val) => parseInt(val, 10)),
  SMTP_USER: z.string().min(1),
  SMTP_PASS: z.string().min(1),
  EMAIL_FROM: z.string(),
});

export const env = envSchema.parse(process.env);
