# 🔐 Node.js Authentication & Authorization API

A production-ready, authentication and authorization system built with Node.js, TypeScript, Express, and PostgreSQL. Features comprehensive security measures including 2FA, JWT tokens, rate limiting, and role-based access control.

## 🌟 Features

### 🔑 Authentication
- **Email/Password Registration** with email verification
- **Google OAuth 2.0** login integration
- **JWT-based authentication** (access + refresh tokens)
- **Token rotation** and blacklisting for enhanced security
- **Password reset** flow with secure token generation
- **Account lockout** after failed login attempts (5 attempts = 15min lockout)
- **Timing attack protection** for login endpoints

### 🛡️ Two-Factor Authentication (2FA)
- **TOTP-based 2FA** using authenticator apps (Google Authenticator, Authy)
- **Backup codes** (8 codes, one-time use, SHA-256 hashed)
- **Rate limiting** on 2FA attempts (5 attempts = 15min lockout)
- **QR code generation** for easy setup
- **Graceful setup flow** with pending secret validation

### 👥 Authorization & Roles
- **Role-based access control (RBAC)**: `USER`, `ADMIN`, `DRIVER`, `RESTAURANT_OWNER`
- **Protected routes** with role middleware
- **Admin dashboard** with user management
- **Driver profiles** with license and vehicle info
- **Restaurant profiles** with business details

### 🖼️ File Uploads
- **Cloudinary integration** for avatar uploads
- **Magic number validation** prevents file type spoofing
- **Automatic image optimization** (size limits, format conversion)
- **Orphaned file cleanup** on upload failures
- **Old avatar deletion** when updating

### 🧹 Data Management
- **Automated cleanup jobs** for expired tokens and old login history
- **Configurable retention policies** (default: 90 days for login history)
- **Cron-based scheduling** with graceful shutdown
- **Manual cleanup scripts** for maintenance

### 📊 Admin Features
- **User management** (list, view, unlock, delete)
- **Role assignment** for users
- **Platform statistics** dashboard
- **Login history tracking** (IP, device, location)
- **Registration history** with device fingerprinting

### 🔒 Security Features
- **Argon2 password hashing** (industry-leading)
- **Helmet.js** for HTTP security headers
- **CORS** with configurable origins
- **Rate limiting** on sensitive endpoints
- **Request ID tracking** for debugging
- **Input validation** with Zod schemas
- **SQL injection protection** via Prisma ORM

## 🛠️ Tech Stack

| Category | Technologies |
|----------|-------------|
| **Runtime** | Node.js 22.x, TypeScript 5.x |
| **Framework** | Express 5.x |
| **Database** | PostgreSQL 16.x, Prisma ORM 7.x |
| **Authentication** | JWT, Google OAuth 2.0, OTPLib (2FA) |
| **File Storage** | Cloudinary |
| **Email** | Nodemailer |
| **Validation** | Zod |
| **Security** | Helmet, Argon2, CORS |
| **Logging** | Winston, Morgan |
| **Jobs** | node-cron |
| **Dev Tools** | ts-node-dev, ESLint, Prettier |

## 📦 Installation

### Prerequisites
- Node.js 22.x or higher
- PostgreSQL 16.x or higher
- pnpm (recommended) or npm
- Cloudinary account (for file uploads)
- Google OAuth credentials (optional)
- SMTP server credentials (for emails)

### Setup

1. **Clone the repository**
```bash
git clone <repository-url>
cd nodejs-authentication-authorization-pt2
```

2. **Install dependencies**
```bash
pnpm install
```

3. **Configure environment variables**
```bash
cp .env.example .env
```

Edit `.env` with your configuration:
```env
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/auth_db

# JWT Secrets (generate with: openssl rand -base64 32)
JWT_ACCESS_SECRET=your-access-secret-here
JWT_REFRESH_SECRET=your-refresh-secret-here

# App
NODE_ENV=development
PORT=3000
APP_URL=http://localhost:3000

# Google OAuth (optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:3000/api/v1/auth/google/callback

# Email
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
EMAIL_FROM=Your App <noreply@yourapp.com>

# Cloudinary
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret

# Cleanup Configuration
CLEANUP_TOKEN_ENABLED=true
CLEANUP_LOGIN_HISTORY_ENABLED=true
LOGIN_HISTORY_RETENTION_DAYS=90
CLEANUP_CRON_SCHEDULE=0 3 * * *
```

4. **Run database migrations**
```bash
pnpm prisma migrate dev
pnpm prisma generate
```

5. **Start development server**
```bash
pnpm dev
```

Server runs on `http://localhost:3000`

## 🚀 Usage

### API Endpoints

#### Authentication
```http
POST   /api/v1/auth/register              # Register new user
POST   /api/v1/auth/login                 # Login with credentials
POST   /api/v1/auth/logout                # Logout (blacklist token)
POST   /api/v1/auth/refresh               # Refresh access token
POST   /api/v1/auth/forgot-password       # Request password reset
POST   /api/v1/auth/reset-password        # Reset password with token
GET    /api/v1/auth/verify-email          # Verify email address
POST   /api/v1/auth/resend-verification   # Resend verification email
GET    /api/v1/auth/google                # Start Google OAuth flow
GET    /api/v1/auth/google/callback       # Google OAuth callback
```

#### Two-Factor Authentication
```http
POST   /api/v1/auth/2fa/setup             # Setup 2FA (get QR code + backup codes)
POST   /api/v1/auth/2fa/verify            # Verify and enable 2FA
POST   /api/v1/auth/2fa/disable           # Disable 2FA (requires password)
```

#### User Management
```http
GET    /api/v1/users/me                   # Get current user profile
PATCH  /api/v1/users/me                   # Update profile
POST   /api/v1/users/me/avatar            # Upload avatar
DELETE /api/v1/users/me/avatar            # Delete avatar
POST   /api/v1/users/register             # Register as USER
POST   /api/v1/users/register/driver      # Register as DRIVER
POST   /api/v1/users/register/restaurant  # Register as RESTAURANT_OWNER
```

#### Admin (ADMIN role required)
```http
GET    /api/v1/admin/stats                # Platform statistics
GET    /api/v1/admin/users                # List all users
GET    /api/v1/admin/users/:id            # Get user details
POST   /api/v1/admin/users/:id/unlock     # Unlock user account
PATCH  /api/v1/admin/users/:id/role       # Update user role
DELETE /api/v1/admin/users/:id            # Delete user
```

### Example Requests

**Register User**
```bash
curl -X POST http://localhost:3000/api/v1/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!@#",
    "name": "John Doe"
  }'
```

**Login**
```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!@#"
  }'
```

**Get Profile (Authenticated)**
```bash
curl http://localhost:3000/api/v1/users/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Setup 2FA**
```bash
curl -X POST http://localhost:3000/api/v1/auth/2fa/setup \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Upload Avatar**
```bash
curl -X POST http://localhost:3000/api/v1/users/me/avatar \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -F "avatar=@profile.jpg"
```

## 📝 Scripts

```bash
# Development
pnpm dev                        # Start dev server with hot reload

# Production
pnpm build                      # Build TypeScript to JavaScript
pnpm start                      # Start production server

# Database
pnpm prisma:migrate            # Run database migrations
pnpm prisma:generate           # Generate Prisma client
pnpm prisma:push               # Push schema to database

# Cleanup Jobs
pnpm cleanup:tokens            # Manually cleanup expired tokens
pnpm cleanup:login-history     # Manually cleanup old login history
pnpm cleanup:all               # Run all cleanup jobs
pnpm scheduler                 # Run cleanup scheduler (standalone)
```

## 🗂️ Project Structure

```
src/
├── admin/                     # Admin module
│   ├── admin.controller.ts
│   ├── admin.service.ts
│   └── admin.schema.ts
├── auth/                      # Authentication module
│   ├── auth.controller.ts
│   ├── auth.service.ts
│   └── auth.schema.ts
├── user/                      # User module
│   ├── user.controller.ts
│   ├── user.service.ts
│   └── user.schema.ts
├── cleanup-scripts/           # Automated cleanup jobs
│   ├── cleanup-tokens.ts
│   ├── cleanup-login-history.ts
│   ├── cleanup-scheduler.ts
│   └── types/
├── config/                    # Configuration
│   ├── env.config.ts
│   ├── email.ts
│   └── cloudinary-config.ts
├── middleware/                # Express middleware
│   ├── auth.ts
│   ├── error-handler.ts
│   ├── request-logger.ts
│   └── upload.middleware.ts
├── lib/                       # Utilities
│   ├── prisma.ts
│   ├── token.ts
│   ├── password-hash.ts
│   └── backup-codes.ts
├── routes/                    # API routes
│   └── v1/
│       ├── auth.routes.ts
│       ├── user.routes.ts
│       └── admin.routes.ts
├── utils/                     # Helpers
│   ├── logger.ts
│   ├── app-error.ts
│   └── async-handler.ts
├── app.ts                     # Express app setup
└── server.ts                  # Server entry point
```

## 🔐 Security Best Practices

### Implemented
- ✅ **Argon2** for password hashing (better than bcrypt)
- ✅ **JWT rotation** with refresh tokens
- ✅ **Token blacklisting** on logout
- ✅ **Token versioning** for instant revocation
- ✅ **Rate limiting** on login, 2FA, password reset
- ✅ **Account lockout** after failed attempts
- ✅ **Timing attack prevention** (constant-time comparisons)
- ✅ **Magic number validation** for file uploads
- ✅ **CORS** and **Helmet** security headers
- ✅ **Input validation** with Zod
- ✅ **SQL injection protection** via Prisma
- ✅ **2FA backup codes** (hashed, one-time use)
- ✅ **Email notifications** for security events
- ✅ **Request ID tracking** for audit logs

### Recommendations for Production
- 🔄 Enable **HTTPS** in production (use nginx/Caddy)
- 🔄 Set up **Redis** for token blacklist (faster than PostgreSQL)
- 🔄 Implement **rate limiting** at nginx/CloudFlare level
- 🔄 Use **secrets manager** (AWS Secrets Manager, HashiCorp Vault)
- 🔄 Enable **database backups** (automated daily)
- 🔄 Set up **monitoring** (Datadog, New Relic, Sentry)
- 🔄 Configure **log aggregation** (ELK stack, CloudWatch)
- 🔄 Use **CI/CD pipeline** (GitHub Actions, GitLab CI)

## 🧪 Testing

```bash
# Unit tests (TODO)
pnpm test

# Integration tests (TODO)
pnpm test:integration

# E2E tests (TODO)
pnpm test:e2e
```

### Manual Testing Checklist

**Authentication Flow**
- [ ] Register new user → Receive verification email
- [ ] Verify email → Account activated
- [ ] Login with correct credentials → Success
- [ ] Login with wrong password 5x → Account locked
- [ ] Request password reset → Receive email
- [ ] Reset password with token → Success
- [ ] Login with new password → Success

**2FA Flow**
- [ ] Setup 2FA → Receive QR code + 8 backup codes
- [ ] Scan QR with authenticator app
- [ ] Verify TOTP code → 2FA enabled
- [ ] Login requires 2FA code → Success
- [ ] Login with backup code → Code consumed
- [ ] Reuse same backup code → Fails
- [ ] Wrong 2FA code 5x → 2FA locked

**File Upload**
- [ ] Upload valid image → Success
- [ ] Upload fake image (renamed .exe) → Rejected
- [ ] Upload oversized image → Rejected
- [ ] Upload new avatar → Old one deleted from Cloudinary

**Cleanup Jobs**
- [ ] Run token cleanup → Expired tokens deleted
- [ ] Run login history cleanup → Old records deleted
- [ ] Check cron runs at scheduled time

## 🐛 Troubleshooting

### Environment Variables Not Loading
```bash
# Add to env.config.ts
import 'dotenv/config';
```

### Database Connection Failed
```bash
# Check PostgreSQL is running
psql -U postgres -c "SELECT version();"

# Verify DATABASE_URL format
postgresql://user:password@localhost:5432/database_name
```

### Cloudinary Upload Fails
```bash
# Verify credentials
node -e "console.log(require('cloudinary').v2.config())"
```

### Emails Not Sending
```bash
# Test SMTP connection
npx nodemailer-smtp-test
```

### TypeScript Errors
```bash
# Regenerate Prisma client
pnpm prisma generate

# Clear build cache
rm -rf dist node_modules/.cache
```

## 📚 Additional Resources

- [Prisma Documentation](https://www.prisma.io/docs)
- [Express.js Guide](https://expressjs.com/en/guide/routing.html)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)

## 📄 License

MIT License - See LICENSE file for details

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📧 Support

For issues and questions:
- Open an issue on GitHub
- Email: support@yourapp.com

---

**Built with ❤️ using Node.js, TypeScript, and PostgreSQL**