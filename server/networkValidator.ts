import net from 'net';
import os from 'os';

export interface NetworkValidationResult {
  available: boolean;
  port: number;
  host: string;
  interfaces: string[];
  message: string;
}

/**
 * Validates whether the specified port is open for binding on host '0.0.0.0'
 * and outputs container network diagnostics.
 */
export async function validatePortAndHost(
  port: number = 3000,
  host: string = '0.0.0.0'
): Promise<NetworkValidationResult> {
  const interfaces = Object.values(os.networkInterfaces())
    .flat()
    .filter((iface): iface is os.NetworkInterfaceInfo => !!iface && !iface.internal && iface.family === 'IPv4')
    .map((iface) => `${iface.address} (${iface.netmask})`);

  return new Promise((resolve) => {
    const tester = net.createServer();

    tester.once('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        resolve({
          available: false,
          port,
          host,
          interfaces,
          message: `[Network Security Gate] Port ${port} is currently bound by another process on ${host}.`,
        });
      } else {
        resolve({
          available: false,
          port,
          host,
          interfaces,
          message: `[Network Security Gate] Binding error on ${host}:${port} - ${err.message}`,
        });
      }
    });

    tester.once('listening', () => {
      tester.close(() => {
        resolve({
          available: true,
          port,
          host,
          interfaces,
          message: `[Network Security Gate] Port ${port} on host ${host} is open and ready for container ingress routing.`,
        });
      });
    });

    tester.listen(port, host);
  });
}

/**
 * Standalone script runner for CLI execution
 */
if (process.argv[1]?.endsWith('networkValidator.ts')) {
  validatePortAndHost(3000, '0.0.0.0').then((result) => {
    console.log(result.message);
    console.log(`[Network Security Gate] Detected IPv4 Interfaces: ${result.interfaces.join(', ') || 'Internal Sandbox Loopback'}`);
    if (!result.available) {
      process.exit(1);
    }
  });
}
