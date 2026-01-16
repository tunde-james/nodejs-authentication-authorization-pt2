import { DeviceInfo } from '../@types/device-info.types';
import { HttpStatus } from '../config/http-status.config';
import { Prisma, Role } from '../generated/prisma/client';
import { hashedPassword } from '../lib/password-hash';
import { prisma } from '../lib/prisma';
import { AppError } from '../utils/app-error';
import {
  RegisterDriverDto,
  RegisterDto,
  RegisterRestaurantDto,
  UpdateProfileDto,
} from './user.schema';

export interface CreatedUser {
  id: string;
  email: string;
  role: Role;
  name: string;
  vehicleType?: string;
  restaurantName?: string;
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
  ): Promise<CreatedUser> {
    const { email, name, password } = registerDto;
    const normalizedEmail = email.toLowerCase().trim();

    if (await this.userExists(normalizedEmail)) {
      throw new AppError('User already exists', HttpStatus.CONFLICT);
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
      select: { id: true, email: true, role: true, name: true },
    });

    return {
      id: newUser.id,
      email: newUser.email,
      name: newUser.name,
      role: newUser.role,
    };
  }

  async createDriver(
    registerDto: RegisterDriverDto,
    deviceInfo: DeviceInfo
  ): Promise<CreatedUser> {
    const { email, name, password, licenseNumber, vehicleType } = registerDto;
    const normalizedEmail = email.toLowerCase().trim();

    return await prisma.$transaction(async (tx) => {
      if (await this.userExists(normalizedEmail, tx)) {
        throw new AppError('User already exists', HttpStatus.CONFLICT);
      }

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
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          driverProfile: { select: { vehicleType: true } },
        },
      });

      return {
        id: newUser.id,
        email: newUser.email,
        role: newUser.role,
        name: newUser.name,
        vehicleType: newUser.driverProfile?.vehicleType ?? undefined,
      };
    });
  }

  async createRestaurant(
    restaurantDto: RegisterRestaurantDto,
    deviceInfo: DeviceInfo
  ): Promise<CreatedUser> {
    const { email, name, password, restaurantName, address } = restaurantDto;
    const normalizedEmail = email.toLowerCase().trim();

    return await prisma.$transaction(async (tx) => {
      if (await this.userExists(normalizedEmail, tx)) {
        throw new AppError('User already exists', HttpStatus.CONFLICT);
      }

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
        select: {
          id: true,
          email: true,
          role: true,
          name: true,
          restaurantProfile: { select: { restaurantName: true } },
        },
      });

      return newUser;
    });
  }

  async getProfile(userId: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        email: true,
        name: true,
        role: true,
        profilePicture: true,
        bio: true,
        phone: true,
        isEmailVerified: true,
        twoFactorEnabled: true,
        driverProfile: {
          select: {
            licenseNumber: true,
            vehicleType: true,
            isVerified: true,
          },
        },
        restaurantProfile: {
          select: {
            restaurantName: true,
            address: true,
            isVerified: true,
          },
        },
      },
    });

    if (!user) {
      throw new AppError('User not found', HttpStatus.NOT_FOUND);
    }

    return user;
  }

  async updateProfile(userId: string, data: UpdateProfileDto) {
    const user = await prisma.user.update({
      where: { id: userId },
      data: {
        name: data.name,
        bio: data.bio,
        phone: data.phone,
      },
      select: {
        email: true,
        name: true,
        role: true,
        profilePicture: true,
        bio: true,
        phone: true,
        updatedAt: true,
      },
    });

    return user;
  }
}
