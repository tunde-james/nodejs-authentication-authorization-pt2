import { HttpStatus } from '../config/http-status.config';
import { prisma } from '../lib/prisma';
import { AppError } from '../utils/app-error';

export class AdminService {
  async getAllUsers() {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        isEmailVerified: true,
        twoFactorEnabled: true,
        profilePicture: true,
        failedLoginAttempts: true,
        lockedUntil: true,
        createdAt: true,
        updatedAt: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    return users;
  }

  async getUserById(userId: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        isEmailVerified: true,
        twoFactorEnabled: true,
        profilePicture: true,
        bio: true,
        phone: true,
        failedLoginAttempts: true,
        lockedUntil: true,
        twoFactorFailedAttempts: true,
        twoFactorLockedUntil: true,
        createdAt: true,
        updatedAt: true,
        loginHistory: {
          take: 10,
          orderBy: { loginTime: 'desc' },
          select: {
            id: true,
            ipAddress: true,
            device: true,
            os: true,
            browser: true,
            country: true,
            city: true,
            loginTime: true,
          },
        },
        registrationHistory: {
          select: {
            ipAddress: true,
            device: true,
            os: true,
            browser: true,
            country: true,
            city: true,
            registeredAt: true,
          },
        },
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

  async unlockUserAccount(userId: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, lockedUntil: true },
    });

    if (!user) {
      throw new AppError('User not found', HttpStatus.NOT_FOUND);
    }

    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: {
        failedLoginAttempts: 0,
        lockedUntil: null,
        twoFactorFailedAttempts: 0,
        twoFactorLockedUntil: null,
      },
      select: {
        id: true,
        email: true,
        name: true,
      },
    });

    return updatedUser;
  }

  async updateUserRole(userId: string, newRole: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, role: true },
    });

    if (!user) {
      throw new AppError('User not found', HttpStatus.NOT_FOUND);
    }

    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: { role: newRole as any },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
      },
    });

    return updatedUser;
  }

  async deleteUser(userId: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, role: true },
    });

    if (!user) {
      throw new AppError('User not found', HttpStatus.NOT_FOUND);
    }

    if (user.role === 'ADMIN') {
      throw (
        new AppError('Cannot delete admin accounts'),
        HttpStatus.FORBIDDEN
      );
    }

    await prisma.user.delete({
      where: { id: userId },
    });

    return { email: user.email };
  }

  async getPlatformStats() {
    const [
      totalUsers,
      verifiedUsers,
      usersWithTwoFactor,
      lockedAccounts,
      recentRegistrations,
      usersByRole,
    ] = await Promise.all([
      prisma.user.count(),

      prisma.user.count({
        where: { isEmailVerified: true },
      }),

      prisma.user.count({
        where: { twoFactorEnabled: true },
      }),

      prisma.user.count({
        where: {
          lockedUntil: {
            gt: new Date(),
          },
        },
      }),

      prisma.user.count({
        where: {
          createdAt: {
            gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
          },
        },
      }),

      prisma.user.groupBy({
        by: ['role'],
        _count: {
          role: true,
        },
      }),
    ]);

    return {
      totalUsers,
      verifiedUsers,
      usersWithTwoFactor,
      lockedAccounts,
      recentRegistrations,
      usersByRole: usersByRole.reduce(
        (acc, curr) => {
          acc[curr.role] = curr._count.role;
          return acc;
        },
        {} as Record<string, number>,
      ),
    };
  }
}
