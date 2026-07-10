import { resolve as dnsResolve } from "node:dns/promises";
import { BlockList, isIP } from "node:net";
import { redactUrl } from "../security/redaction.js";

const NON_GLOBAL_RANGES = [
  { address: "0.0.0.0", prefix: 8, type: "ipv4" as const },
  { address: "10.0.0.0", prefix: 8, type: "ipv4" as const },
  { address: "100.64.0.0", prefix: 10, type: "ipv4" as const },
  { address: "127.0.0.0", prefix: 8, type: "ipv4" as const },
  { address: "169.254.0.0", prefix: 16, type: "ipv4" as const },
  { address: "172.16.0.0", prefix: 12, type: "ipv4" as const },
  { address: "192.0.0.0", prefix: 24, type: "ipv4" as const },
  { address: "192.0.2.0", prefix: 24, type: "ipv4" as const },
  { address: "192.88.99.0", prefix: 24, type: "ipv4" as const },
  { address: "192.168.0.0", prefix: 16, type: "ipv4" as const },
  { address: "198.18.0.0", prefix: 15, type: "ipv4" as const },
  { address: "198.51.100.0", prefix: 24, type: "ipv4" as const },
  { address: "203.0.113.0", prefix: 24, type: "ipv4" as const },
  { address: "224.0.0.0", prefix: 4, type: "ipv4" as const },
  { address: "240.0.0.0", prefix: 4, type: "ipv4" as const },
  { address: "::", prefix: 128, type: "ipv6" as const },
  { address: "::1", prefix: 128, type: "ipv6" as const },
  { address: "::ffff:0:0", prefix: 96, type: "ipv6" as const },
  { address: "64:ff9b::", prefix: 96, type: "ipv6" as const },
  { address: "64:ff9b:1::", prefix: 48, type: "ipv6" as const },
  { address: "100::", prefix: 64, type: "ipv6" as const },
  { address: "2001::", prefix: 23, type: "ipv6" as const },
  { address: "2001:db8::", prefix: 32, type: "ipv6" as const },
  { address: "2002::", prefix: 16, type: "ipv6" as const },
  { address: "3fff::", prefix: 20, type: "ipv6" as const },
  { address: "5f00::", prefix: 16, type: "ipv6" as const },
  { address: "fc00::", prefix: 7, type: "ipv6" as const },
  { address: "fe80::", prefix: 10, type: "ipv6" as const },
  { address: "fec0::", prefix: 10, type: "ipv6" as const },
  { address: "ff00::", prefix: 8, type: "ipv6" as const },
];

const NON_GLOBAL_IPV4_BLOCKS = new BlockList();
const NON_GLOBAL_IPV6_BLOCKS = new BlockList();
for (const range of NON_GLOBAL_RANGES) {
  const blocks = range.type === "ipv4" ? NON_GLOBAL_IPV4_BLOCKS : NON_GLOBAL_IPV6_BLOCKS;
  blocks.addSubnet(range.address, range.prefix, range.type);
}

export type PublicTarget = {
  url: URL;
  addresses: Array<{ address: string; family: 4 | 6 }>;
};

function stripIpv6Brackets(hostname: string): string {
  return hostname.replace(/^\[(.*)]$/, "$1");
}

function rawHostname(url: string): string {
  const match = url.match(/^[a-z][a-z0-9+.-]*:\/\/(?:[^/?#@]*@)?(\[[^\]]+]|[^:/?#]+)/i);
  return match ? stripIpv6Brackets(match[1]) : "";
}

function isNonStandardNumericHost(hostname: string): boolean {
  const standardIpv4 = hostname.split(".").length === 4
    && hostname.split(".").every((part) => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
  return !standardIpv4 && /^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+))*$/i.test(hostname);
}

function isGlobalAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return !NON_GLOBAL_IPV4_BLOCKS.check(address, "ipv4");
  if (family === 6) return !NON_GLOBAL_IPV6_BLOCKS.check(address, "ipv6");
  return false;
}

export function remaining(deadline: number): number {
  return Math.max(0, deadline - Date.now());
}

function beforeDeadline<T>(operation: Promise<T>, deadline: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const wait = remaining(deadline);
    if (wait === 0) {
      reject(new Error("Request timed out"));
      return;
    }

    const timer = setTimeout(() => reject(new Error("Request timed out")), wait);
    operation.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      }
    );
  });
}

export async function resolvePublicTarget(
  url: string,
  deadline: number,
  origin?: string,
  allowPrivate = false
): Promise<PublicTarget> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`URL not allowed (${redactUrl(url)})`);
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`URL not allowed (${redactUrl(url)})`);
  }
  if (origin && parsed.origin !== new URL(origin).origin) {
    throw new Error(`Cross-origin URL blocked (${redactUrl(url)})`);
  }

  const rawHost = rawHostname(url);
  if (rawHost && isNonStandardNumericHost(rawHost)) {
    throw new Error(`URL not allowed (${redactUrl(url)})`);
  }

  const hostname = stripIpv6Brackets(parsed.hostname);
  if (!allowPrivate && (/^(?:.*\.)?localhost$/i.test(hostname) || /^metadata\.google\.internal$/i.test(hostname))) {
    throw new Error(`URL not allowed (${redactUrl(url)})`);
  }

  const literalFamily = isIP(hostname);
  if (literalFamily) {
    if (!allowPrivate && !isGlobalAddress(hostname)) {
      throw new Error(`URL not allowed (${redactUrl(url)})`);
    }
    return { url: parsed, addresses: [{ address: hostname, family: literalFamily as 4 | 6 }] };
  }

  const answers = await beforeDeadline(Promise.allSettled([
    dnsResolve(hostname, "A"),
    dnsResolve(hostname, "AAAA"),
  ]), deadline);
  const addresses = [...new Set(answers.flatMap((answer) =>
    answer.status === "fulfilled" ? answer.value : []
  ))];

  if (addresses.length === 0 || (!allowPrivate && addresses.some((address) => !isGlobalAddress(address)))) {
    throw new Error(`URL not allowed (${redactUrl(url)})`);
  }

  return {
    url: parsed,
    addresses: addresses.map((address) => ({
      address,
      family: isIP(address) as 4 | 6,
    })),
  };
}
