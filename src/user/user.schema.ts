import { z } from 'zod';

export const registerSchema = z.object({
  email: z.string().email('Invalid email format'),
  name: z.string().min(2, 'Name must be at least 2 characters'),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .regex(
      /[^A-Za-z0-9]/,
      'Password must contain at least one special character'
    ),
});

export const registerDriverSchema = registerSchema.extend({
  licenseNumber: z
    .string()
    .min(5, 'License number must be at least 5 characters'),
  vehicleType: z.string().min(3, 'Vehicle type must be at least 3 characters'),
});

export const registerRestaurantSchema = registerSchema.extend({
  restaurantName: z
    .string()
    .min(2, 'Restaurant name must be at least 2 characters'),
  address: z.string().min(5, 'Address must be at least 5 characters'),
});

export const updateProfileSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters').optional(),
  bio: z.string().max(500, 'Bio must be at least 500 characters').optional(),
  phone: z
    .string()
    .regex(/^\+?[1-9]\d{6,14}$/, 'Invalid phone number format')
    .optional(),
});

export type RegisterDto = z.infer<typeof registerSchema>;
export type RegisterDriverDto = z.infer<typeof registerDriverSchema>;
export type RegisterRestaurantDto = z.infer<typeof registerRestaurantSchema>;
export type UpdateProfileDto = z.infer<typeof updateProfileSchema>;
