import { config } from 'dotenv';

import { hashedPassword } from '../../lib/password-hash';
import { prisma } from '../../lib/prisma';

config();

const createAdmin = async () => {
  const email = process.argv[2];
  const password = process.argv[3];
  const name = process.argv[4] || 'Admin User';

  if (!email || !password) {
    console.error('Usage: npm run create-admin <email> <password> [name]');
    process.exit(1);
  }

  const normalizedEmail = email.toLowerCase().trim();

  const emailExists = await prisma.user.findUnique({
    where: { email: normalizedEmail },
  });

  if (emailExists) {
    console.log('User exists. Upgrading to ADMIN...');

    await prisma.user.update({
      where: { email: normalizedEmail },
      data: { role: 'ADMIN', isEmailVerified: true },
    });

    console.log(`✅ User ${email} upgraded to ADMIN`);
  } else {
    console.log('Creating new admin user...');

    const passwordHash = await hashedPassword(password);

    await prisma.user.create({
      data: {
        email: normalizedEmail,
        name,
        passwordHash,
        role: 'ADMIN',
        isEmailVerified: true,
      },
    });

    console.log(`✅ Admin user created: ${email}`);
  }

  await prisma.$disconnect();
};

createAdmin().catch((error) => {
  console.error('Error:', error);
  process.exit(1);
});

// pnpm run create-admin admin@foodapp.com Admin123!@# "Admin User"
