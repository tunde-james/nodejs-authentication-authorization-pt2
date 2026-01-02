import { DeviceInfo } from '../@types/jwt.types';
import { Role } from '../@types/role.types';
import { hashedPassword } from '../lib/password-hash';
import { prisma } from '../lib/prisma';
import { RegisterDto } from './user.schema';

export interface CreatedUser {
  id: string;
  email: string;
  role: Role;
}

export class UserService {
  private createRegistrationHistoryData(deviceInfo: DeviceInfo) {
    return {
      ipAddress: deviceInfo.ipAddress,
      userAgent: deviceInfo.userAgent,
      device: deviceInfo.device,
      os: deviceInfo.os,
      browser: deviceInfo.browser,
      country: deviceInfo.country,
      city: deviceInfo.city,
    };
  }

  async userExists(email: string): Promise<boolean> {
    const normalizedEmail = email.toLowerCase().trim();
    const user = await prisma.user.findUnique({
      where: { email: normalizedEmail },
    });
    return !!user;
  }

  async createUser(
    registerDto: RegisterDto,
    deviceInfo: DeviceInfo
  ): Promise<CreatedUser | null> {
    const { email, name, password } = registerDto;
    const normalizedEmail = email.toLowerCase().trim();

    if (await this.userExists(normalizedEmail)) {
      return null;
    }

    const passwordHash = await hashedPassword(password);

    const newUser = await prisma.user.create({
      data: {
        email: normalizedEmail,
        name,
        passwordHash,
        role: 'USER',
        registrationHistory: {
          create: this.createRegistrationHistoryData(deviceInfo),
        },
      },
      select: { id: true, email: true, role: true },
    });

    return newUser;
  }
}
