export interface DeviceInfo {
  ipAddress: string;
  userAgent: string;
  device: string;
  os: string;
  browser: string;
  country: string | null;
  city: string | null;
}
