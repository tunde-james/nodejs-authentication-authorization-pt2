import { Router } from 'express';

import * as authController from '../../auth/auth.controller';
import { asyncHandler } from '../../utils/async-handler';

const router = Router();

/**
 * @swagger
 * tags:
 *   name: Auth
 *   description: Authentication API
 */

/**
 * @swagger
 * /auth/verify-email:
 *   get:
 *     summary: Verify user email
 *     tags: [Auth]
 *     parameters:
 *       - in: query
 *         name: token
 *         schema:
 *           type: string
 *         required: true
 *         description: Email verification token
 *     responses:
 *       200:
 *         description: Email verified
 *       400:
 *         description: Invalid token
 */
router.get('/verify-email', asyncHandler(authController.verifyEmail));

/**
 * @swagger
 * /auth/resend-verification:
 *   post:
 *     summary: Resend verification email
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email]
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *     responses:
 *       200:
 *         description: Verification email sent
 *       404:
 *         description: User not found
 */
router.post(
  '/resend-verification',
  asyncHandler(authController.resendVerificationEmail)
);

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Login user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *               twoFactorCode:
 *                 type: string
 *                 description: Required if 2FA is enabled
 *     responses:
 *       200:
 *         description: Login successful
 *       401:
 *         description: Invalid credentials
 *       429:
 *         description: Account locked due to too many failed attempts
 */
router.post('/login', asyncHandler(authController.login));

/**
 * @swagger
 * /auth/refresh:
 *   post:
 *     summary: Refresh access token
 *     tags: [Auth]
 *     description: Accepts refresh token via cookie or request body (for mobile clients)
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               refreshToken:
 *                 type: string
 *                 description: Required for mobile clients without cookie support
 *     responses:
 *       200:
 *         description: Token refreshed
 *       401:
 *         description: Invalid or expired refresh token
 */
router.post('/refresh', asyncHandler(authController.refreshToken));
router.post('/refresh/mobile', asyncHandler(authController.refreshTokenMobile));

/**
 * @swagger
 * /auth/logout:
 *   post:
 *     summary: Logout user
 *     tags: [Auth]
 *     responses:
 *       200:
 *         description: Logged out successfully
 */
router.post('/logout', asyncHandler(authController.logout));

router.get('/google', asyncHandler(authController.googleAuthStartHandler));
router.get(
  '/google/callback',
  asyncHandler(authController.googleAuthCallbackHandler)
);

export default router;
