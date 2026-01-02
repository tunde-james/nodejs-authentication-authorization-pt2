import { DeviceInfo } from '../@types/jwt.types';
import { Role } from '../@types/role.types';
import { Prisma } from '../generated/prisma/client';
import { hashedPassword } from '../lib/password-hash';
import { prisma } from '../lib/prisma';
import {
  RegisterDriverDto,
  RegisterDto,
  RegisterRestaurantDto,
} from './user.schema';

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

  async userExists(
    email: string,
    tx?: Prisma.TransactionClient
  ): Promise<boolean> {
    const client = tx || prisma;
    const normalizedEmail = email.toLowerCase().trim();
    const user = await client.user.findUnique({
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

  async createDriver(
    registerDto: RegisterDriverDto,
    deviceInfo: DeviceInfo
  ): Promise<CreatedUser | null> {
    const { email, name, password, licenseNumber, vehicleType } = registerDto;
    const normalizedEmail = email.toLowerCase().trim();

    return await prisma.$transaction(async (tx) => {
      if (await this.userExists(normalizedEmail, tx)) return null; // Now checks inside tx

      const passwordHash = await hashedPassword(password);

      const newUser = await tx.user.create({
        data: {
          email: normalizedEmail,
          name,
          passwordHash,
          role: 'DRIVER',
          driverProfile: {
            create: {
              licenseNumber,
              vehicleType,
            },
          },
          registrationHistory: {
            create: this.createRegistrationHistoryData(deviceInfo),
          },
        },
        select: { id: true, email: true, role: true },
      });

      return newUser;
    });
  }

  async createRestaurant(
    restaurantDto: RegisterRestaurantDto,
    deviceInfo: DeviceInfo
  ): Promise<CreatedUser | null> {
    const { email, name, password, restaurantName, address } = restaurantDto;
    const normalizedEmail = email.toLowerCase().trim();

    return await prisma.$transaction(async (tx) => {
      if (await this.userExists(normalizedEmail, tx)) return null;

      const passwordHash = await hashedPassword(password);

      const newUser = await tx.user.create({
        data: {
          email: normalizedEmail,
          name,
          passwordHash,
          role: 'RESTAURANT_OWNER',
          restaurantProfile: {
            create: {
              restaurantName,
              address,
            },
          },
          registrationHistory: {
            create: this.createRegistrationHistoryData(deviceInfo),
          },
        },
        select: { id: true, email: true, role: true },
      });

      return newUser;
    });
  }
}
