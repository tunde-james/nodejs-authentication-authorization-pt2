import { z } from 'zod';

/**
 * Schema for updating user role
 */
export const updateUserRoleSchema = z.object({
  role: z.enum(['USER', 'ADMIN', 'DRIVER', 'RESTAURANT_OWNER'], {
    message: 'Role must be one of: USER, ADMIN, DRIVER, RESTAURANT_OWNER',
  }),
});

export type UpdateUserRoleDto = z.infer<typeof updateUserRoleSchema>;
