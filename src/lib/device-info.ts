import geoip from 'geoip-lite';
import useragent from 'useragent';

export function extractDeviceInfo(ipAddress: string, userAgentString: string) {
  const agent = useragent.parse(userAgentString);

  const fallback = (val: string) =>
    val !== 'Other 0.0.0' ? val : 'Unknown (RAW UA: ' + userAgentString + ')';

  let geo = null;

  if (ipAddress !== '::1' && ipAddress !== '127.0.0.1') {
    geo = geoip.lookup(ipAddress);
  }

  return {
    ipAddress,
    userAgent: userAgentString,
    device: fallback(agent.device.toString()) || 'Unknown',
    os: fallback(agent.os.toString()) || 'Unknown',
    browser: fallback(agent.toAgent()) || 'Unknown',
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
      : forwarded.split(',')[0].trim();

    return ips;
  }

  return req.ip || req.socket?.remoteAddress || 'Unknown';
}
