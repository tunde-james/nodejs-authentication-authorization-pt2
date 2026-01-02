import { Role } from '../@types/role.types';

const WELCOME_MESSAGES: Record<Role, string> = {
  USER: 'Welcome to our platform!',
  ADMIN: 'Welcome, Admin!',
  DRIVER: 'Welcome, Driver!',
  RESTAURANT_OWNER: 'Welcome, Restaurant Owner',
};

export const sendVerificationEmail = async (
  userId: string,
  email: string,
  role: Role
): Promise<void> => {};
