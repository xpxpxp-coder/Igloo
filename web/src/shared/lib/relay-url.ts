/** Convert a WebSocket relay URL to its HTTP equivalent. */
export function relayHttpUrl(wsUrl: string): string {
  if (wsUrl.startsWith("wss://")) {
    return `https://${wsUrl.slice(6)}`;
  }
  if (wsUrl.startsWith("ws://")) {
    return `http://${wsUrl.slice(5)}`;
  }
  return wsUrl;
}

/** Read the relay WebSocket URL from environment or derive from window.location. */
export function relayWsUrl(): string {
  const envUrl = import.meta.env.VITE_RELAY_URL;
  if (envUrl) return requireSnowmanRelayUrl(envUrl);
  // Same-origin: derive from current page location (works when served from relay)
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return requireSnowmanRelayUrl(`${proto}//${window.location.host}`);
}

function requireSnowmanRelayUrl(raw: string): string {
  const parsed = new URL(raw);
  if (parsed.username || parsed.password) {
    throw new Error("Snowman relay URLs must not contain credentials.");
  }
  if (import.meta.env.DEV === true) return raw;
  const host = parsed.hostname.toLowerCase();
  if (
    parsed.protocol !== "wss:" ||
    (host !== "snowmanai.org" && !host.endsWith(".snowmanai.org"))
  ) {
    throw new Error("Relay URL is outside the Snowman-controlled boundary.");
  }
  return raw;
}

/** HTTP base URL for the relay (derived from the WS URL). */
export function relayHttpBaseUrl(): string {
  return relayHttpUrl(relayWsUrl());
}
