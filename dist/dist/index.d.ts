import * as node_tls from 'node:tls';
import * as http from 'node:http';
import * as net from 'node:net';

/** Route info used by the proxy server to map hostnames to ports. */
interface RouteInfo {
    hostname: string;
    port: number;
}
interface ProxyServerOptions {
    /** Called on each request to get the current route table. */
    getRoutes: () => RouteInfo[];
    /** The port the proxy is listening on (used to build correct URLs). */
    proxyPort: number;
    /** TLD suffix used for hostnames (default: "localhost"). */
    tld?: string;
    /**
     * When true, only exact hostname matches are used. Unregistered subdomain
     * prefixes return 404 instead of falling back to the base service.
     * Defaults to true.
     */
    strict?: boolean;
    /** Optional error logger; defaults to console.error. */
    onError?: (message: string) => void;
    /** When provided, enables HTTP/2 over TLS (HTTPS). */
    tls?: {
        cert: Buffer;
        key: Buffer;
        /** CA certificate to include in the chain so clients can verify the leaf. */
        ca?: Buffer;
        /** SNI callback for per-hostname certificate selection. */
        SNICallback?: (servername: string, cb: (err: Error | null, ctx?: node_tls.SecureContext) => void) => void;
    };
}

/** Response header used to identify a portless proxy (for health checks). */
declare const PORTLESS_HEADER = "X-Portless";
/** Server type returned by createProxyServer (plain HTTP/1.1 or net.Server TLS wrapper). */
type ProxyServer = http.Server | net.Server;
/**
 * Create an HTTP proxy server that routes requests based on the Host header.
 *
 * Uses Node's built-in http module for proxying (no external dependencies).
 * The `getRoutes` callback is invoked on every request so callers can provide
 * either a static list or a live-updating one.
 *
 * When `tls` is provided, creates an HTTP/2 secure server with HTTP/1.1
 * fallback (`allowHTTP1: true`). This enables HTTP/2 multiplexing for
 * browsers while keeping WebSocket upgrades working over HTTP/1.1.
 */
declare function createProxyServer(options: ProxyServerOptions): ProxyServer;
/**
 * Create a minimal HTTP server that 302-redirects every request to HTTPS.
 * Meant to run on port 80 alongside an HTTPS proxy on port 443.
 */
declare function createHttpRedirectServer(httpsPort: number): http.Server;

/** File permission mode for route and state files. */
declare const FILE_MODE = 420;
/** Directory permission mode for the state directory. */
declare const DIR_MODE = 493;
interface RouteMapping extends RouteInfo {
    pid: number;
    tailscaleUrl?: string;
    tailscaleHttpsPort?: number;
    tailscaleFunnel?: boolean;
}
/**
 * Thrown when a route is already registered by a live process and --force was
 * not specified. With --force, the existing process is killed instead.
 */
declare class RouteConflictError extends Error {
    readonly hostname: string;
    readonly existingPid: number;
    constructor(hostname: string, existingPid: number);
}
/**
 * Manages route mappings stored as a JSON file on disk.
 * Supports file locking and stale-route cleanup.
 */
declare class RouteStore {
    /** The state directory path. */
    readonly dir: string;
    private readonly routesPath;
    private readonly lockPath;
    readonly pidPath: string;
    readonly portFilePath: string;
    private readonly onWarning;
    constructor(dir: string, options?: {
        onWarning?: (message: string) => void;
    });
    ensureDir(): void;
    getRoutesPath(): string;
    private static readonly sleepBuffer;
    private syncSleep;
    private acquireLock;
    private releaseLock;
    private isProcessAlive;
    /**
     * Load routes from disk, filtering out stale entries whose owning process
     * is no longer alive. Stale-route cleanup is only persisted when the caller
     * already holds the lock (i.e. inside addRoute/removeRoute) to avoid
     * unprotected concurrent writes.
     */
    loadRoutes(persistCleanup?: boolean): RouteMapping[];
    private saveRoutes;
    /**
     * Register a route. When `force` is true and the hostname is already claimed
     * by another live process, that process is sent SIGTERM before the route is
     * replaced. Returns the PID of the killed process (if any) so the caller can
     * log it.
     */
    addRoute(hostname: string, port: number, pid: number, force?: boolean): number | undefined;
    /**
     * Load all routes from disk without filtering out dead PIDs. Used by
     * `portless prune` to discover stale entries whose owning CLI is gone
     * but whose dev server may still be holding a port.
     */
    loadRoutesRaw(): RouteMapping[];
    /**
     * Remove all route entries whose owning process is dead and persist the
     * result. Returns the removed stale entries so the caller can act on them.
     */
    pruneStaleRoutes(): RouteMapping[];
    /**
     * Update metadata on an existing route entry. Only provided fields are
     * merged; the route must already exist (matched by hostname).
     */
    updateRoute(hostname: string, fields: Partial<Pick<RouteMapping, "tailscaleUrl" | "tailscaleHttpsPort" | "tailscaleFunnel">>): void;
    removeRoute(hostname: string): void;
}

/**
 * When running under sudo, fix file ownership so the real user can
 * read/write the file later without sudo. No-op on Windows or when not
 * running as root.
 */
declare function fixOwnership(...paths: string[]): void;
/** Type guard for Node.js system errors with an error code. */
declare function isErrnoException(err: unknown): err is NodeJS.ErrnoException;
/**
 * Escape HTML special characters to prevent XSS.
 */
declare function escapeHtml(str: string): string;
/**
 * Format a URL for the given hostname. Omits the port when it matches the
 * protocol default (80 for HTTP, 443 for HTTPS).
 */
declare function formatUrl(hostname: string, proxyPort: number, tls?: boolean): string;
/**
 * Parse and normalize a hostname input for use as a subdomain of the
 * configured TLD. Strips protocol prefixes, validates characters, and
 * appends the TLD suffix if needed.
 */
declare function parseHostname(input: string, tld?: string): string;

/**
 * Extract the portless-managed block from /etc/hosts content.
 * Returns the lines between the markers (exclusive), or an empty array
 * if no managed block exists.
 */
declare function extractManagedBlock(content: string): string[];
/**
 * Remove the portless-managed block from /etc/hosts content and return
 * the cleaned content with trailing newlines normalized.
 */
declare function removeBlock(content: string): string;
/**
 * Build a portless-managed block for the given hostnames.
 */
declare function buildBlock(hostnames: string[]): string;
/**
 * Whether the proxy should write route hostnames to the hosts file.
 * Disabled only when `PORTLESS_SYNC_HOSTS` is `0` or `false` (opt-out).
 */
declare function shouldAutoSyncHosts(syncVal: string | undefined): boolean;
/**
 * Sync /etc/hosts to include entries for all given hostnames.
 * Replaces any existing portless-managed block. Requires root access.
 * Returns true on success, false on failure.
 */
declare function syncHostsFile(hostnames: string[]): boolean;
/**
 * Remove the portless-managed block from /etc/hosts.
 * Returns true on success, false on failure.
 */
declare function cleanHostsFile(): boolean;
/**
 * Return the current portless-managed hostnames from /etc/hosts.
 */
declare function getManagedHostnames(): string[];
/**
 * Check whether a hostname resolves to 127.0.0.1 via the system DNS resolver.
 * Returns true if resolution works, false otherwise.
 */
declare function checkHostResolution(hostname: string): Promise<boolean>;

export { DIR_MODE, FILE_MODE, PORTLESS_HEADER, type ProxyServer, type ProxyServerOptions, RouteConflictError, type RouteInfo, type RouteMapping, RouteStore, buildBlock, checkHostResolution, cleanHostsFile, createHttpRedirectServer, createProxyServer, escapeHtml, extractManagedBlock, fixOwnership, formatUrl, getManagedHostnames, isErrnoException, parseHostname, removeBlock, shouldAutoSyncHosts, syncHostsFile };
