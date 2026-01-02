import geoip from 'geoip-lite';
import useragent from 'useragent';

export function extractDeviceInfo(ipAddress: string, userAgentString: string) {
  const agent = useragent.parse(userAgentString);
  const geo = geoip.lookup(ipAddress);

  return {
    ipAddress,
    userAgent: userAgentString,
    device: agent.device.toString() || 'Unknown',
    os: agent.os.toString() || 'Unknown',
    browser: agent.toAgent() || 'Unknown',
    country: geo?.country || null,
    city: geo?.city || null,
  };
}

export function getClientIp(req: {
  ip?: string;
  socket?: { remoteAddress?: string };
  headers?: { 'x-forwarded-for'?: string | string[]; [key: string]: any };
}): string {
  const forwarded = req.headers?.['x-forwarded-for'];
  if (forwarded) {
    const ips = Array.isArray(forwarded)
      ? forwarded[0]
      : forwarded.split(',')[0];

    return ips.trim();
  }

  return req.ip || req.socket?.remoteAddress || 'Unknown';
}
