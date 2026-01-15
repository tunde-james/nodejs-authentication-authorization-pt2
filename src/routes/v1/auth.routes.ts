import { Router } from 'express';

import * as authController from '../../auth/auth.controller';
import { asyncHandler } from '../../utils/async-handler';
import { requireAuth } from '../../middleware/auth';

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

/**
 * @swagger
 * /auth/google:
 *   get:
 *     summary: Start Google OAuth login flow
 *     tags: [Auth]
 *     description: Redirects to Google's authorization page to start OAuth2 login. Use this to initiate sign-in with Google.
 *     parameters:
 *       - in: query
 *         name: redirectUri
 *         schema:
 *           type: string
 *         required: false
 *         description: Custom redirect URI after Google auth (defaults to env.GOOGLE_REDIRECT_URI)
 *     responses:
 *       302:
 *         description: Redirects to Google auth URL
 *       500:
 *         description: Internal error if env vars are missing
 */
router.get('/google', asyncHandler(authController.googleAuthStartHandler));

/**
 * @swagger
 * /auth/google/callback:
 *   get:
 *     summary: Handle Google OAuth callback
 *     tags: [Auth]
 *     description: Processes the authorization code from Google, exchanges for tokens, and logs in or registers the user. This is called by Google after user consent.
 *     parameters:
 *       - in: query
 *         name: code
 *         schema:
 *           type: string
 *         required: true
 *         description: Authorization code from Google
 *       - in: query
 *         name: state
 *         schema:
 *           type: string
 *         required: false
 *         description: Optional state parameter for CSRF protection
 *       - in: query
 *         name: redirectUri
 *         schema:
 *           type: string
 *         required: false
 *         description: Custom redirect URI (if provided in initial request)
 *     responses:
 *       200:
 *         description: Login successful, returns accessToken and user info
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                 accessToken:
 *                   type: string
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     email:
 *                       type: string
 *                     name:
 *                       type: string
 *                     role:
 *                       type: string
 *       400:
 *         description: Missing code or invalid Google response
 *       401:
 *         description: Invalid or unverified Google email
 */
router.get(
  '/google/callback',
  asyncHandler(authController.googleAuthCallbackHandler)
);

/**
 * @swagger
 * /auth/forgot-password:
 *   post:
 *     summary: Request password reset
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
 *         description: Reset email sent (if account exists)
 */
router.post('/forgot-password', asyncHandler(authController.forgotPassword));

/**
 * @swagger
 * /auth/reset-password:
 *   post:
 *     summary: Reset password
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [token, password]
 *             properties:
 *               token:
 *                 type: string
 *               password:
 *                 type: string
 *                 minLength: 8
 *     responses:
 *       200:
 *         description: Password reset successful
 *       400:
 *         description: Invalid token
 */
router.post('/reset-password', asyncHandler(authController.resetPassword));

/**
 * @swagger
 * /auth/2fa/setup:
 *   post:
 *     summary: Setup two-factor authentication
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: 2FA setup data (secret and QR code URL)
 *       401:
 *         description: Not authenticated
 */
router.post('/2fa/setup', requireAuth, asyncHandler(authController.setup2FA));

/**
 * @swagger
 * /auth/2fa/verify:
 *   post:
 *     summary: Verify and enable 2FA
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [code]
 *             properties:
 *               code:
 *                 type: string
 *                 description: 6-digit TOTP code
 *     responses:
 *       200:
 *         description: 2FA enabled
 *       400:
 *         description: Invalid code
 */
router.post('/2fa/verify', requireAuth, asyncHandler(authController.verify2FA));

/**
 *  @swagger
 * /auth/2fa/disable:
 *   post:
 *     summary: Disable two-factor authentication
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [password]
 *             properties:
 *               password:
 *                 type: string
 *                 description: User's current password for verification
 *     responses:
 *       200:
 *         description: 2FA disabled successfully
 *       400:
 *         description: 2FA not enabled or missing password
 *       401:
 *         description: Invalid password
 */
router.post(
  '/2fa/disable',
  requireAuth,
  asyncHandler(authController.disable2FA)
);

export default router;
