import QRCode from 'qrcode';

const otpAuthUrl = process.argv[2];
if (!otpAuthUrl) {
  throw new Error('Pass otpAuthUrl as argument');
}

async function main() {
  await QRCode.toFile('totp.png', otpAuthUrl);
  console.log('Saved QR Code');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

// To generate a QR cod:
// 1. Get totp url from the 2FA setup endpoint response
// 2. Run: pnpm dlx ts-node scripts/totp-qr.ts "otpauth://totp/NodeAdvancedAuthApp:tundejames%40example.com?secret=OJ3R2GZ4D5ICGK3M&period=30&digits=6&algorithm=SHA1&issuer=NodeAdvancedAuthApp" 