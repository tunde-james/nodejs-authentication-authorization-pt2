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

/**
 * @swagger
 * /users/register/driver:
 *   post:
 *     summary: Register a new driver
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password, name, licenseNumber, vehicleType]
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *               licenseNumber:
 *                 type: string
 *               vehicleType:
 *                 type: string
 *     responses:
 *       201:
 *         description: Registration successful
 */
router.post('/register/driver', asyncHandler(userController.registerDriver));

/**
 * @swagger
 * /users/register/restaurant:
 *   post:
 *     summary: Register a new restaurant owner
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password, name, restaurantName, address]
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *               restaurantName:
 *                 type: string
 *               address:
 *                 type: string
 *     responses:
 *       201:
 *         description: Registration successful
 */
router.post(
  '/register/restaurant',
  asyncHandler(userController.registerRestaurant)
);

export default router;
