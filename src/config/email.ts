import nodemailer from 'nodemailer';
import SMTPTransport from 'nodemailer/lib/smtp-transport';

import { env } from './env.config';

export const sendEmail = async (to: string, subject: string, html: string) => {
  if (!env.SMTP_HOST || !env.SMTP_USER || !env.SMTP_PASS) {
    return;
  }

  const config: SMTPTransport.Options = {
    host: env.SMTP_HOST,
    port: Number(env.SMTP_PORT || '465'),
    secure: false,
    auth: {
      user: env.SMTP_USER,
      pass: env.SMTP_PASS,
    },
  };

  const transporter = nodemailer.createTransport(config);

  await transporter.sendMail({
    from: env.EMAIL_FROM,
    to,
    subject,
    html,
  });
};
