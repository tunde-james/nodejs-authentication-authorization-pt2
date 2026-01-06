import { Response } from 'express';
import { env } from '../config/env.config';
import { HttpStatus } from '../config/http-status.config';

export const handleVerificationResponse = (
  res: Response,
  success: boolean,
  message: string
) => {
  if (env.FRONTEND_URL && env.FRONTEND_URL !== 'none') {
    const status = success ? 'success' : 'error';

    return res.redirect(
      `${
        env.FRONTEND_URL
      }/auth/verify-email?status=${status}&message=${encodeURIComponent(
        message
      )}`
    );
  }

  const statusCode = success ? HttpStatus.OK : HttpStatus.BAD_REQUEST;
  const statusClass = success ? 'success' : 'error';
  const icon = success ? '✅' : '❌';
  const title = success ? 'Email verified' : 'Verification Failed';

  return res.status(statusCode).send(`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${title}</title>
        <style>
          * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
          }
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
          }
          .container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            padding: 48px;
            max-width: 500px;
            width: 100%;
            text-align: center;
          }
          .icon {
            font-size: 64px;
            margin-bottom: 24px;
          }
          h1 {
            font-size: 28px;
            margin-bottom: 16px;
            color: #1a202c;
          }
          p {
            font-size: 16px;
            line-height: 1.6;
            color: #4a5568;
            margin-bottom: 32px;
          }
          .success {
            color: #48bb78;
          }
          .error {
            color: #f56565;
          }
          .btn {
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 12px 32px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            transition: background 0.2s;
          }
          .btn:hover {
            background: #5568d3;
          }
          .footer {
            margin-top: 32px;
            font-size: 14px;
            color: #718096;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="icon">${icon}</div>
          <h1 class="${statusClass}">${title}</h1>
          <p>${message}</p>
          ${
            success
              ? '<p class="footer">You can now close this window and log in to your account.</p>'
              : '<p class="footer">Need help? Contact support or try requesting a new verification email.</p>'
          }
        </div>
      </body>
    </html>
    `);
};
