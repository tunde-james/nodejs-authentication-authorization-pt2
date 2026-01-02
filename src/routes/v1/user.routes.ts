import { Router } from 'express';

import { asyncHandler } from '../../utils/async-handler';
import * as userController from '../../user/user.controller';

const router = Router();

/**
 * @swagger
 * tags:
 *   name: User
 *   description: User management and profile API
 */

/**
 * @swagger
 * /users/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password, name]
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 minLength: 8
 *                 description: Must contain uppercase, lowercase, number, and special character
 *               name:
 *                 type: string
 *                 minLength: 2
 *     responses:
 *       201:
 *         description: Registration successful (check email for verification)
 */
router.post('/register', asyncHandler(userController.register));

export default router;
