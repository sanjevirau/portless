#!/usr/bin/env node
import {
  FILE_MODE,
  PORTLESS_HEADER,
  RouteConflictError,
  RouteStore,
  cleanHostsFile,
  createHttpRedirectServer,
  createProxyServer,
  fixOwnership,
  formatUrl,
  isErrnoException,
  parseHostname,
  shouldAutoSyncHosts,
  syncHostsFile
} from "./chunk-3IFWOJM6.js";

// src/colors.ts
function supportsColor() {
  if ("NO_COLOR" in process.env) return false;
  if ("FORCE_COLOR" in process.env) return true;
  return !!(process.stdout.isTTY || process.stderr.isTTY);
}
var enabled = supportsColor();
var wrap = (open, close) => {
  if (!enabled) return (s) => s;
  return (s) => `\x1B[${open}m${s}\x1B[${close}m`;
};
var identity = (s) => s;
var bold = wrap("1", "22");
var dim = wrap("2", "22");
var red = wrap("31", "39");
var green = identity;
var yellow = wrap("33", "39");
var blue = Object.assign(identity, { bold });
var cyan = Object.assign(identity, { bold });
var white = identity;
var gray = dim;
var colors_default = { bold, dim, red, green, yellow, blue, cyan, white, gray };

// src/cli.ts
import * as fs8 from "fs";
import * as path8 from "path";
import { spawn as spawn3, spawnSync as spawnSync3 } from "child_process";
import { StringDecoder } from "string_decoder";

// src/certs.ts
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import * as tls from "tls";
import { execFile as execFileCb, execFileSync } from "child_process";
import { promisify } from "util";
var CA_VALIDITY_DAYS = 3650;
var SERVER_VALIDITY_DAYS = 365;
var EXPIRY_BUFFER_MS = 7 * 24 * 60 * 60 * 1e3;
var CA_COMMON_NAME = "portless Local CA";
var OPENSSL_TIMEOUT_MS = 15e3;
var MACOS_SECURITY_TIMEOUT_MS = 15e3;
var MACOS_SECURITY_AUTH_TIMEOUT_MS = 12e4;
var MACOS_SECURITY_ROOT_TIMEOUT_MS = 6e4;
var CA_KEY_FILE = "ca-key.pem";
var CA_CERT_FILE = "ca.pem";
var SERVER_KEY_FILE = "server-key.pem";
var SERVER_CERT_FILE = "server.pem";
var CA_TRUST_MARKER = "ca.trusted";
function fileExists(filePath) {
  try {
    fs.accessSync(filePath, fs.constants.R_OK);
    return true;
  } catch {
    return false;
  }
}
function caFingerprint(stateDir) {
  const caCertPath = path.join(stateDir, CA_CERT_FILE);
  try {
    const pem = fs.readFileSync(caCertPath);
    return crypto.createHash("sha256").update(pem).digest("hex");
  } catch {
    return null;
  }
}
function readTrustMarker(stateDir) {
  try {
    const value = fs.readFileSync(path.join(stateDir, CA_TRUST_MARKER), "utf-8").trim();
    return value || null;
  } catch {
    return null;
  }
}
function writeTrustMarker(stateDir) {
  const fp = caFingerprint(stateDir);
  if (fp) {
    fs.writeFileSync(path.join(stateDir, CA_TRUST_MARKER), fp + "\n");
    fixOwnership(path.join(stateDir, CA_TRUST_MARKER));
  }
}
function clearTrustMarker(stateDir) {
  try {
    fs.unlinkSync(path.join(stateDir, CA_TRUST_MARKER));
  } catch {
  }
}
var _opensslEnv;
function getOpensslEnv() {
  if (process.platform !== "win32") return void 0;
  if (_opensslEnv !== void 0) return _opensslEnv;
  if (process.env.OPENSSL_CONF && fileExists(process.env.OPENSSL_CONF)) {
    _opensslEnv = {};
    return _opensslEnv;
  }
  const candidates = [
    // Git-for-Windows bundles OpenSSL here
    path.join("C:", "Program Files", "Git", "mingw64", "etc", "ssl", "openssl.cnf"),
    path.join("C:", "Program Files", "Git", "usr", "ssl", "openssl.cnf"),
    // Standalone OpenSSL installers
    path.join("C:", "Program Files", "OpenSSL-Win64", "bin", "cnf", "openssl.cnf"),
    path.join("C:", "Program Files", "OpenSSL-Win64", "openssl.cnf"),
    path.join("C:", "Program Files (x86)", "OpenSSL-Win32", "bin", "cnf", "openssl.cnf"),
    // Common winget/chocolatey install paths
    path.join("C:", "Program Files", "OpenSSL", "bin", "cnf", "openssl.cnf")
  ];
  for (const candidate of candidates) {
    if (fileExists(candidate)) {
      _opensslEnv = { OPENSSL_CONF: candidate };
      return _opensslEnv;
    }
  }
  _opensslEnv = {};
  return _opensslEnv;
}
function opensslErrorMessage() {
  if (process.platform === "win32") {
    return "Make sure openssl is installed and working.\nInstall via: winget install -e --id ShiningLight.OpenSSL.Dev\nIf already installed, set OPENSSL_CONF to the path of your openssl.cnf file.";
  }
  return "Make sure openssl is installed (ships with macOS and most Linux distributions).";
}
function isCertValid(certPath) {
  try {
    const pem = fs.readFileSync(certPath, "utf-8");
    const cert = new crypto.X509Certificate(pem);
    const expiry = new Date(cert.validTo).getTime();
    return Date.now() + EXPIRY_BUFFER_MS < expiry;
  } catch {
    return false;
  }
}
function isCertSansComplete(certPath) {
  try {
    const text = openssl(["x509", "-in", certPath, "-noout", "-text"]);
    return /DNS:\*\.local\b/.test(text);
  } catch {
    return false;
  }
}
function isCertSignatureStrong(certPath) {
  try {
    const text = openssl(["x509", "-in", certPath, "-noout", "-text"]);
    const match = text.match(/Signature Algorithm:\s*(\S+)/i);
    if (!match) return false;
    const algo = match[1].toLowerCase();
    return !algo.includes("sha1");
  } catch {
    return false;
  }
}
function openssl(args, options) {
  try {
    const extraEnv = getOpensslEnv();
    return execFileSync("openssl", args, {
      encoding: "utf-8",
      timeout: OPENSSL_TIMEOUT_MS,
      input: options?.input,
      stdio: ["pipe", "pipe", "pipe"],
      ...extraEnv && Object.keys(extraEnv).length > 0 ? { env: { ...process.env, ...extraEnv } } : {}
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`openssl failed: ${message}

${opensslErrorMessage()}`);
  }
}
var execFileAsync = promisify(execFileCb);
async function opensslAsync(args) {
  try {
    const extraEnv = getOpensslEnv();
    const { stdout } = await execFileAsync("openssl", args, {
      encoding: "utf-8",
      timeout: OPENSSL_TIMEOUT_MS,
      ...extraEnv && Object.keys(extraEnv).length > 0 ? { env: { ...process.env, ...extraEnv } } : {}
    });
    return stdout;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`openssl failed: ${message}

${opensslErrorMessage()}`);
  }
}
function generateCA(stateDir) {
  const keyPath = path.join(stateDir, CA_KEY_FILE);
  const certPath = path.join(stateDir, CA_CERT_FILE);
  openssl(["ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", keyPath]);
  openssl([
    "req",
    "-new",
    "-x509",
    "-sha256",
    "-key",
    keyPath,
    "-out",
    certPath,
    "-days",
    CA_VALIDITY_DAYS.toString(),
    "-subj",
    `/CN=${CA_COMMON_NAME}`,
    "-addext",
    "basicConstraints=critical,CA:TRUE",
    "-addext",
    "keyUsage=critical,keyCertSign,cRLSign"
  ]);
  fs.chmodSync(keyPath, 384);
  fs.chmodSync(certPath, 420);
  fixOwnership(keyPath, certPath);
  clearTrustMarker(stateDir);
  return { certPath, keyPath };
}
function generateServerCert(stateDir) {
  const caKeyPath = path.join(stateDir, CA_KEY_FILE);
  const caCertPath = path.join(stateDir, CA_CERT_FILE);
  const serverKeyPath = path.join(stateDir, SERVER_KEY_FILE);
  const serverCertPath = path.join(stateDir, SERVER_CERT_FILE);
  const csrPath = path.join(stateDir, "server.csr");
  const extPath = path.join(stateDir, "server-ext.cnf");
  openssl(["ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", serverKeyPath]);
  openssl(["req", "-new", "-key", serverKeyPath, "-out", csrPath, "-subj", "/CN=localhost"]);
  const sans = ["DNS:localhost", "DNS:*.localhost", "DNS:*.local"];
  fs.writeFileSync(
    extPath,
    [
      "authorityKeyIdentifier=keyid,issuer",
      "basicConstraints=CA:FALSE",
      "keyUsage=digitalSignature,keyEncipherment",
      "extendedKeyUsage=serverAuth",
      `subjectAltName=${sans.join(",")}`
    ].join("\n") + "\n"
  );
  const srlPath = path.join(stateDir, "ca.srl");
  if (!fileExists(srlPath)) {
    fs.writeFileSync(
      srlPath,
      crypto.randomUUID().replace(/-/g, "").slice(0, 16).toUpperCase() + "\n"
    );
  }
  openssl([
    "x509",
    "-req",
    "-sha256",
    "-in",
    csrPath,
    "-CA",
    caCertPath,
    "-CAkey",
    caKeyPath,
    "-CAserial",
    srlPath,
    "-out",
    serverCertPath,
    "-days",
    SERVER_VALIDITY_DAYS.toString(),
    "-extfile",
    extPath
  ]);
  for (const tmp of [csrPath, extPath]) {
    try {
      fs.unlinkSync(tmp);
    } catch {
    }
  }
  fs.chmodSync(serverKeyPath, 384);
  fs.chmodSync(serverCertPath, 420);
  fixOwnership(serverKeyPath, serverCertPath);
  return { certPath: serverCertPath, keyPath: serverKeyPath };
}
function ensureCerts(stateDir) {
  const caCertPath = path.join(stateDir, CA_CERT_FILE);
  const caKeyPath = path.join(stateDir, CA_KEY_FILE);
  const serverCertPath = path.join(stateDir, SERVER_CERT_FILE);
  const serverKeyPath = path.join(stateDir, SERVER_KEY_FILE);
  let caGenerated = false;
  const caMissing = !fileExists(caCertPath) || !fileExists(caKeyPath) || !isCertValid(caCertPath) || !isCertSignatureStrong(caCertPath);
  if (caMissing) {
    generateCA(stateDir);
    caGenerated = true;
  }
  if (caGenerated || !fileExists(serverCertPath) || !fileExists(serverKeyPath) || !isCertValid(serverCertPath) || !isCertSignatureStrong(serverCertPath) || !isCertSansComplete(serverCertPath)) {
    generateServerCert(stateDir);
  }
  return {
    certPath: serverCertPath,
    keyPath: serverKeyPath,
    caPath: caCertPath,
    caGenerated
  };
}
function isCATrusted(stateDir) {
  const caCertPath = path.join(stateDir, CA_CERT_FILE);
  if (!fileExists(caCertPath)) return false;
  const marker = readTrustMarker(stateDir);
  if (marker) {
    const fp = caFingerprint(stateDir);
    if (fp && marker === fp) return true;
  }
  if (process.platform === "darwin") {
    return isCATrustedMacOS(caCertPath);
  } else if (process.platform === "linux") {
    return isCATrustedLinux(stateDir);
  } else if (process.platform === "win32") {
    return isCATrustedWindows(caCertPath);
  }
  return false;
}
function isCATrustedWindows(caCertPath) {
  try {
    const fingerprint = openssl(["x509", "-in", caCertPath, "-noout", "-fingerprint", "-sha1"]).trim().replace(/^.*=/, "").replace(/:/g, "").toLowerCase();
    const result = execFileSync("certutil", ["-store", "-user", "Root"], {
      encoding: "utf-8",
      timeout: 1e4,
      stdio: ["pipe", "pipe", "pipe"]
    });
    return result.replace(/\s/g, "").toLowerCase().includes(fingerprint);
  } catch {
    return false;
  }
}
function isCATrustedMacOS(caCertPath) {
  try {
    const isRoot = (process.getuid?.() ?? -1) === 0;
    const sudoUser = process.env.SUDO_USER;
    if (isRoot && sudoUser) {
      execFileSync(
        "sudo",
        ["-u", sudoUser, "security", "verify-cert", "-c", caCertPath, "-L", "-p", "ssl"],
        {
          stdio: "pipe",
          timeout: MACOS_SECURITY_TIMEOUT_MS
        }
      );
    } else {
      execFileSync("security", ["verify-cert", "-c", caCertPath, "-L", "-p", "ssl"], {
        stdio: "pipe",
        timeout: MACOS_SECURITY_TIMEOUT_MS
      });
    }
    return true;
  } catch {
    return false;
  }
}
function loginKeychainPath() {
  try {
    const result = execFileSync("security", ["default-keychain"], {
      encoding: "utf-8",
      timeout: MACOS_SECURITY_TIMEOUT_MS
    }).trim();
    const match = result.match(/"(.+)"/);
    if (match) return match[1];
  } catch {
  }
  const home = process.env.HOME || `/Users/${process.env.USER || "unknown"}`;
  return path.join(home, "Library", "Keychains", "login.keychain-db");
}
var LINUX_CA_TRUST_CONFIGS = {
  debian: {
    certDir: "/usr/local/share/ca-certificates",
    updateCommand: "update-ca-certificates"
  },
  arch: {
    certDir: "/etc/ca-certificates/trust-source/anchors",
    updateCommand: "update-ca-trust"
  },
  fedora: {
    certDir: "/etc/pki/ca-trust/source/anchors",
    updateCommand: "update-ca-trust"
  },
  suse: {
    certDir: "/etc/pki/trust/anchors",
    updateCommand: "update-ca-certificates"
  }
};
function detectLinuxDistro() {
  try {
    const osRelease = fs.readFileSync("/etc/os-release", "utf-8").toLowerCase();
    if (osRelease.includes("arch")) return "arch";
    if (osRelease.includes("fedora") || osRelease.includes("rhel") || osRelease.includes("centos"))
      return "fedora";
    if (osRelease.includes("suse")) return "suse";
    if (osRelease.includes("debian") || osRelease.includes("ubuntu")) return "debian";
  } catch {
  }
  for (const [distro, config] of Object.entries(LINUX_CA_TRUST_CONFIGS)) {
    try {
      execFileSync("which", [config.updateCommand], { stdio: "pipe", timeout: 5e3 });
      if (fs.existsSync(path.dirname(config.certDir))) return distro;
    } catch {
    }
  }
  return void 0;
}
function getLinuxCATrustConfig() {
  const distro = detectLinuxDistro();
  return LINUX_CA_TRUST_CONFIGS[distro ?? "debian"];
}
function isCATrustedLinux(stateDir) {
  const config = getLinuxCATrustConfig();
  const systemCertPath = path.join(config.certDir, "portless-ca.crt");
  if (!fileExists(systemCertPath)) return false;
  try {
    const ours = fs.readFileSync(path.join(stateDir, CA_CERT_FILE), "utf-8").trim();
    const installed = fs.readFileSync(systemCertPath, "utf-8").trim();
    return ours === installed;
  } catch {
    return false;
  }
}
var HOST_CERTS_DIR = "host-certs";
function sanitizeHostForFilename(hostname) {
  return hostname.replace(/\./g, "_").replace(/[^a-z0-9_-]/gi, "");
}
var MAX_CN_LENGTH = 64;
async function generateHostCertAsync(stateDir, hostname) {
  const caKeyPath = path.join(stateDir, CA_KEY_FILE);
  const caCertPath = path.join(stateDir, CA_CERT_FILE);
  const hostDir = path.join(stateDir, HOST_CERTS_DIR);
  if (!fs.existsSync(hostDir)) {
    await fs.promises.mkdir(hostDir, { recursive: true, mode: 493 });
    fixOwnership(hostDir);
  }
  const safeName = sanitizeHostForFilename(hostname);
  const keyPath = path.join(hostDir, `${safeName}-key.pem`);
  const certPath = path.join(hostDir, `${safeName}.pem`);
  const csrPath = path.join(hostDir, `${safeName}.csr`);
  const extPath = path.join(hostDir, `${safeName}-ext.cnf`);
  await opensslAsync(["ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", keyPath]);
  const cn = hostname.length > MAX_CN_LENGTH ? hostname.slice(0, MAX_CN_LENGTH) : hostname;
  await opensslAsync(["req", "-new", "-key", keyPath, "-out", csrPath, "-subj", `/CN=${cn}`]);
  const sans = [`DNS:${hostname}`];
  const parts = hostname.split(".");
  if (parts.length >= 2) {
    sans.push(`DNS:*.${parts.slice(1).join(".")}`);
  }
  await fs.promises.writeFile(
    extPath,
    [
      "authorityKeyIdentifier=keyid,issuer",
      "basicConstraints=CA:FALSE",
      "keyUsage=digitalSignature,keyEncipherment",
      "extendedKeyUsage=serverAuth",
      `subjectAltName=${sans.join(",")}`
    ].join("\n") + "\n"
  );
  const srlPath = path.join(stateDir, "ca.srl");
  if (!fs.existsSync(srlPath)) {
    await fs.promises.writeFile(
      srlPath,
      crypto.randomUUID().replace(/-/g, "").slice(0, 16).toUpperCase() + "\n"
    );
  }
  await opensslAsync([
    "x509",
    "-req",
    "-sha256",
    "-in",
    csrPath,
    "-CA",
    caCertPath,
    "-CAkey",
    caKeyPath,
    "-CAserial",
    srlPath,
    "-out",
    certPath,
    "-days",
    SERVER_VALIDITY_DAYS.toString(),
    "-extfile",
    extPath
  ]);
  for (const tmp of [csrPath, extPath]) {
    try {
      await fs.promises.unlink(tmp);
    } catch {
    }
  }
  await fs.promises.chmod(keyPath, 384);
  await fs.promises.chmod(certPath, 420);
  fixOwnership(keyPath, certPath);
  return { certPath, keyPath };
}
function createSNICallback(stateDir, defaultCert, defaultKey, tld = "localhost", caCert) {
  const cache = /* @__PURE__ */ new Map();
  const pending = /* @__PURE__ */ new Map();
  const defaultCtx = tls.createSecureContext({
    cert: caCert ? Buffer.concat([defaultCert, caCert]) : defaultCert,
    key: defaultKey
  });
  return (servername, cb) => {
    if (servername === tld) {
      cb(null, defaultCtx);
      return;
    }
    if (cache.has(servername)) {
      cb(null, cache.get(servername));
      return;
    }
    const safeName = sanitizeHostForFilename(servername);
    const hostDir = path.join(stateDir, HOST_CERTS_DIR);
    const certPath = path.join(hostDir, `${safeName}.pem`);
    const keyPath = path.join(hostDir, `${safeName}-key.pem`);
    if (fileExists(certPath) && fileExists(keyPath) && isCertValid(certPath) && isCertSignatureStrong(certPath)) {
      try {
        const hostCert = fs.readFileSync(certPath);
        const ctx = tls.createSecureContext({
          cert: caCert ? Buffer.concat([hostCert, caCert]) : hostCert,
          key: fs.readFileSync(keyPath)
        });
        cache.set(servername, ctx);
        cb(null, ctx);
        return;
      } catch {
      }
    }
    if (pending.has(servername)) {
      pending.get(servername).then((ctx) => cb(null, ctx)).catch((err) => cb(err instanceof Error ? err : new Error(String(err))));
      return;
    }
    const promise = generateHostCertAsync(stateDir, servername).then(async (generated) => {
      const [hostCert, key] = await Promise.all([
        fs.promises.readFile(generated.certPath),
        fs.promises.readFile(generated.keyPath)
      ]);
      return tls.createSecureContext({
        cert: caCert ? Buffer.concat([hostCert, caCert]) : hostCert,
        key
      });
    });
    pending.set(servername, promise);
    promise.then((ctx) => {
      cache.set(servername, ctx);
      pending.delete(servername);
      cb(null, ctx);
    }).catch((err) => {
      pending.delete(servername);
      cb(err instanceof Error ? err : new Error(String(err)));
    });
  };
}
function trustCA(stateDir) {
  const caCertPath = path.join(stateDir, CA_CERT_FILE);
  if (!fileExists(caCertPath)) {
    return {
      trusted: false,
      error: "CA certificate not found. Run portless trust to generate it."
    };
  }
  try {
    if (process.platform === "darwin") {
      const isRoot = (process.getuid?.() ?? -1) === 0;
      if (isRoot) {
        execFileSync(
          "security",
          [
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            "/Library/Keychains/System.keychain",
            caCertPath
          ],
          { stdio: "pipe", timeout: MACOS_SECURITY_ROOT_TIMEOUT_MS }
        );
      } else {
        const keychain = loginKeychainPath();
        execFileSync(
          "security",
          ["add-trusted-cert", "-r", "trustRoot", "-k", keychain, caCertPath],
          { stdio: "pipe", timeout: MACOS_SECURITY_AUTH_TIMEOUT_MS }
        );
      }
      writeTrustMarker(stateDir);
      return { trusted: true };
    } else if (process.platform === "linux") {
      const config = getLinuxCATrustConfig();
      if (!fs.existsSync(config.certDir)) {
        fs.mkdirSync(config.certDir, { recursive: true });
      }
      const dest = path.join(config.certDir, "portless-ca.crt");
      fs.copyFileSync(caCertPath, dest);
      execFileSync(config.updateCommand, [], { stdio: "pipe", timeout: 3e4 });
      writeTrustMarker(stateDir);
      return { trusted: true };
    } else if (process.platform === "win32") {
      execFileSync("certutil", ["-addstore", "-user", "Root", caCertPath], {
        stdio: "pipe",
        timeout: 3e4
      });
      writeTrustMarker(stateDir);
      return { trusted: true };
    }
    return { trusted: false, error: `Unsupported platform: ${process.platform}` };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes("ETIMEDOUT")) {
      const hint = process.platform === "darwin" ? "The macOS security command timed out. This can happen when the Keychain Services daemon is unresponsive or a system authorization dialog was not dismissed in time. Try restarting Keychain Access (or run: sudo killall securityd) and then: portless trust" : "The trust command timed out. Try: portless trust";
      return { trusted: false, error: hint };
    }
    if (message.includes("authorization") || message.includes("permission") || message.includes("EACCES")) {
      return {
        trusted: false,
        error: "Permission denied. Try: portless trust"
      };
    }
    return { trusted: false, error: message };
  }
}
function untrustCA(stateDir) {
  const caCertPath = path.join(stateDir, CA_CERT_FILE);
  if (!fileExists(caCertPath)) {
    clearTrustMarker(stateDir);
    return { removed: true };
  }
  if (!isCATrusted(stateDir)) {
    clearTrustMarker(stateDir);
    return { removed: true };
  }
  try {
    let result;
    if (process.platform === "darwin") {
      result = untrustCAMacOS(caCertPath);
    } else if (process.platform === "linux") {
      result = untrustCALinux(stateDir);
    } else if (process.platform === "win32") {
      result = untrustCAWindows(caCertPath);
    } else {
      result = { removed: false, error: `Unsupported platform: ${process.platform}` };
    }
    if (result.removed) clearTrustMarker(stateDir);
    return result;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { removed: false, error: message };
  }
}
function untrustCAMacOS(caCertPath) {
  const errors = [];
  const tryExec = (args) => {
    try {
      execFileSync("security", args, { stdio: "pipe", timeout: MACOS_SECURITY_ROOT_TIMEOUT_MS });
      return true;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      errors.push(message);
      return false;
    }
  };
  tryExec(["remove-trusted-cert", caCertPath]);
  const keychains = [loginKeychainPath(), "/Library/Keychains/System.keychain"];
  for (const kc of keychains) {
    for (let i = 0; i < 20; i++) {
      if (!tryExec(["delete-certificate", "-c", CA_COMMON_NAME, kc])) break;
    }
  }
  return isCATrustedMacOSAfterAttempt(caCertPath) ? { removed: false, error: errors.join("; ") || "Could not remove CA from keychain (try sudo)" } : { removed: true };
}
function isCATrustedMacOSAfterAttempt(caCertPath) {
  try {
    const isRoot = (process.getuid?.() ?? -1) === 0;
    const sudoUser = process.env.SUDO_USER;
    if (isRoot && sudoUser) {
      execFileSync(
        "sudo",
        ["-u", sudoUser, "security", "verify-cert", "-c", caCertPath, "-L", "-p", "ssl"],
        { stdio: "pipe", timeout: MACOS_SECURITY_TIMEOUT_MS }
      );
    } else {
      execFileSync("security", ["verify-cert", "-c", caCertPath, "-L", "-p", "ssl"], {
        stdio: "pipe",
        timeout: MACOS_SECURITY_TIMEOUT_MS
      });
    }
    return true;
  } catch {
    return false;
  }
}
function untrustCALinux(stateDir) {
  const errors = [];
  let deletedAny = false;
  for (const config of Object.values(LINUX_CA_TRUST_CONFIGS)) {
    const dest = path.join(config.certDir, "portless-ca.crt");
    try {
      if (fileExists(dest)) {
        const ours = fs.readFileSync(path.join(stateDir, CA_CERT_FILE), "utf-8").trim();
        const installed = fs.readFileSync(dest, "utf-8").trim();
        if (ours === installed) {
          fs.unlinkSync(dest);
          deletedAny = true;
        }
      }
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err));
    }
  }
  if (deletedAny) {
    try {
      const config = getLinuxCATrustConfig();
      execFileSync(config.updateCommand, [], { stdio: "pipe", timeout: 3e4 });
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err));
    }
  }
  if (isCATrusted(stateDir)) {
    return {
      removed: false,
      error: errors.join("; ") || "CA still trusted (remove portless-ca.crt and run the distro CA update command, often with sudo)"
    };
  }
  return { removed: true };
}
function untrustCAWindows(caCertPath) {
  try {
    const fingerprint = openssl(["x509", "-in", caCertPath, "-noout", "-fingerprint", "-sha1"]).trim().replace(/^.*=/, "").replace(/:/g, "").toLowerCase();
    const storeListing = execFileSync("certutil", ["-store", "-user", "Root"], {
      encoding: "utf-8",
      timeout: 1e4,
      stdio: ["pipe", "pipe", "pipe"]
    });
    const normalized = storeListing.replace(/\s/g, "").toLowerCase();
    if (!normalized.includes(fingerprint)) {
      return { removed: true };
    }
    execFileSync("certutil", ["-delstore", "-user", "Root", "portless Local CA"], {
      stdio: "pipe",
      timeout: 3e4
    });
    if (isCATrustedWindows(caCertPath)) {
      return { removed: false, error: "certutil could not remove the portless CA from Root" };
    }
    return { removed: true };
  } catch (err) {
    return { removed: false, error: err instanceof Error ? err.message : String(err) };
  }
}

// src/tailscale.ts
import { spawnSync } from "child_process";
var TAILSCALE_BINARY = "tailscale";
var PREFERRED_SERVE_PORTS = [443, 8443, 8444, 8445, 8446, 8447, 8448, 8449, 8450];
var FUNNEL_PORTS = [443, 8443, 1e4];
function defaultRunner(args) {
  const result = spawnSync(TAILSCALE_BINARY, args, { encoding: "utf-8" });
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    ...result.error ? { error: result.error } : {}
  };
}
function trimDot(value) {
  return value.endsWith(".") ? value.slice(0, -1) : value;
}
function normalizeSpace(value) {
  return value.trim().replace(/\s+/g, " ");
}
function runOrThrow(args, action, runner) {
  const result = runner(args);
  if (result.error) {
    const errno = result.error;
    if (errno.code === "ENOENT") {
      throw new Error(
        "Tailscale CLI not found. Install Tailscale (https://tailscale.com/download) and ensure `tailscale` is on PATH."
      );
    }
    throw new Error(`Failed to ${action}: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const details = normalizeSpace(result.stderr || result.stdout);
    throw new Error(`Failed to ${action}: ${details || "unknown tailscale error"}`);
  }
  return result;
}
function parseStatusJson(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error("Failed to parse `tailscale status --json` output.");
  }
}
function statusToDnsName(status) {
  const dnsName = status.Self?.DNSName;
  if (typeof dnsName === "string" && dnsName.length > 0) {
    return trimDot(dnsName);
  }
  const host = status.Self?.HostName;
  const suffix = status.CurrentTailnet?.MagicDNSSuffix;
  if (typeof host === "string" && host.length > 0 && typeof suffix === "string" && suffix.length > 0) {
    return `${host}.${trimDot(suffix)}`;
  }
  throw new Error(
    "Could not determine Tailscale node DNS name from `tailscale status --json`. Is Tailscale connected?"
  );
}
function ensureTailscaleReady(runner = defaultRunner) {
  runOrThrow(["version"], "check tailscale version", runner);
  const statusResult = runOrThrow(["status", "--json"], "read tailscale status", runner);
  const status = parseStatusJson(statusResult.stdout);
  const dnsName = statusToDnsName(status);
  return {
    dnsName,
    baseUrl: `https://${dnsName}`
  };
}
function getUsedServePorts(runner = defaultRunner) {
  const result = runner(["serve", "status", "--json"]);
  if (result.error || result.status !== 0) {
    return /* @__PURE__ */ new Set();
  }
  try {
    const config = JSON.parse(result.stdout);
    const ports = /* @__PURE__ */ new Set();
    if (config.Web) {
      for (const hostPort of Object.keys(config.Web)) {
        const match = hostPort.match(/:(\d+)$/);
        if (match) {
          ports.add(parseInt(match[1], 10));
        }
      }
    }
    if (config.TCP) {
      for (const portStr of Object.keys(config.TCP)) {
        const p = parseInt(portStr, 10);
        if (!isNaN(p)) ports.add(p);
      }
    }
    return ports;
  } catch {
    return /* @__PURE__ */ new Set();
  }
}
function findAvailableServePort(usedPorts, mode = "serve") {
  const pool = mode === "funnel" ? FUNNEL_PORTS : PREFERRED_SERVE_PORTS;
  for (const port2 of pool) {
    if (!usedPorts.has(port2)) return port2;
  }
  if (mode === "funnel") {
    throw new Error(
      "All Tailscale Funnel ports are in use (443, 8443, 10000). Stop an existing funnel to free a port."
    );
  }
  let port = PREFERRED_SERVE_PORTS[PREFERRED_SERVE_PORTS.length - 1] + 1;
  while (usedPorts.has(port)) port++;
  return port;
}
function isConflictError(stderr, stdout) {
  const text = `${stderr}
${stdout}`.toLowerCase();
  return text.includes("already in use") || text.includes("already exists") || text.includes("port conflict") || text.includes("address already");
}
var CONFLICT_MESSAGES = {
  serve: "Stop the existing serve or let portless auto-assign a different port.",
  funnel: "Tailscale Funnel supports ports 443, 8443, and 10000."
};
function register(mode, localPort, httpsPort, runner) {
  const target = `http://127.0.0.1:${localPort}`;
  const result = runner([mode, "--bg", "--yes", `--https=${httpsPort}`, target]);
  if (result.error) {
    const errno = result.error;
    if (errno.code === "ENOENT") {
      throw new Error(
        "Tailscale CLI not found. Install Tailscale (https://tailscale.com/download) and ensure `tailscale` is on PATH."
      );
    }
    throw new Error(`Failed to register tailscale ${mode}: ${result.error.message}`);
  }
  if (result.status !== 0) {
    if (isConflictError(result.stderr, result.stdout)) {
      throw new Error(
        `Tailscale ${mode === "funnel" ? "Funnel " : ""}HTTPS port ${httpsPort} is already in use. ` + CONFLICT_MESSAGES[mode]
      );
    }
    const details = normalizeSpace(result.stderr || result.stdout);
    throw new Error(
      `Failed to register tailscale ${mode} on port ${httpsPort}: ${details || "unknown tailscale error"}`
    );
  }
}
function unregister(mode, httpsPort, options) {
  const runner = options?.runner ?? defaultRunner;
  const result = runner([mode, "--yes", `--https=${httpsPort}`, "off"]);
  if (result.error) {
    const errno = result.error;
    if (errno.code === "ENOENT") return;
    throw new Error(`Failed to remove tailscale ${mode}: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const text = `${result.stderr}
${result.stdout}`.toLowerCase();
    const looksLikeMissing = text.includes("not found") || text.includes("no serve config") || text.includes("nothing to remove") || text.includes("does not exist");
    if (options?.ignoreMissing && looksLikeMissing) return;
    const details = normalizeSpace(result.stderr || result.stdout);
    throw new Error(
      `Failed to remove tailscale ${mode} on port ${httpsPort}: ${details || "unknown tailscale error"}`
    );
  }
}
function registerServe(localPort, httpsPort, options) {
  register("serve", localPort, httpsPort, options?.runner ?? defaultRunner);
}
function registerFunnel(localPort, httpsPort, options) {
  register("funnel", localPort, httpsPort, options?.runner ?? defaultRunner);
}
function unregisterTailscale(route) {
  if (!route.tailscaleHttpsPort) return;
  const mode = route.tailscaleFunnel ? "funnel" : "serve";
  unregister(mode, route.tailscaleHttpsPort, { ignoreMissing: true });
}
function formatTailscaleUrl(baseUrl, httpsPort) {
  const trimmed = baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl;
  if (httpsPort === 443) return trimmed;
  return `${trimmed}:${httpsPort}`;
}

// src/auto.ts
import { createHash as createHash2 } from "crypto";
import { execFileSync as execFileSync2 } from "child_process";
import * as fs2 from "fs";
import * as path2 from "path";
var MAX_DNS_LABEL_LENGTH = 63;
function truncateLabel(label) {
  if (label.length <= MAX_DNS_LABEL_LENGTH) return label;
  const hash = createHash2("sha256").update(label).digest("hex").slice(0, 6);
  const maxPrefixLength = MAX_DNS_LABEL_LENGTH - 7;
  const prefix = label.slice(0, maxPrefixLength).replace(/-+$/, "");
  return `${prefix}-${hash}`;
}
function sanitizeForHostname(name) {
  const sanitized = name.toLowerCase().replace(/[^a-z0-9-]/g, "-").replace(/-{2,}/g, "-").replace(/^-+|-+$/g, "");
  return truncateLabel(sanitized);
}
function inferProjectName(cwd = process.cwd()) {
  const pkgResult = findPackageJsonName(cwd);
  if (pkgResult) {
    const sanitized2 = sanitizeForHostname(pkgResult);
    if (sanitized2) {
      return { name: sanitized2, source: "package.json" };
    }
  }
  const gitRoot = findGitRoot(cwd);
  if (gitRoot) {
    const sanitized2 = sanitizeForHostname(path2.basename(gitRoot));
    if (sanitized2) {
      return { name: sanitized2, source: "git root" };
    }
  }
  const sanitized = sanitizeForHostname(path2.basename(cwd));
  if (sanitized) {
    return { name: sanitized, source: "directory name" };
  }
  throw new Error("Could not infer a project name from package.json, git root, or directory name");
}
function findPackageJsonName(startDir) {
  let dir = startDir;
  for (; ; ) {
    const pkgPath = path2.join(dir, "package.json");
    try {
      const raw = fs2.readFileSync(pkgPath, "utf-8");
      const pkg = JSON.parse(raw);
      if (typeof pkg.name === "string" && pkg.name) {
        return pkg.name.replace(/^@[^/]+\//, "");
      }
    } catch {
    }
    const parent = path2.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}
function findGitRoot(startDir) {
  try {
    const toplevel = execFileSync2("git", ["rev-parse", "--show-toplevel"], {
      cwd: startDir,
      encoding: "utf-8",
      timeout: 5e3,
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
    if (toplevel) return toplevel;
  } catch {
  }
  let dir = startDir;
  for (; ; ) {
    const gitPath = path2.join(dir, ".git");
    try {
      const stat = fs2.statSync(gitPath);
      if (stat.isDirectory()) return dir;
      if (stat.isFile()) return dir;
    } catch {
    }
    const parent = path2.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}
var DEFAULT_BRANCHES = /* @__PURE__ */ new Set(["main", "master"]);
function branchToPrefix(branch) {
  if (!branch || branch === "HEAD" || DEFAULT_BRANCHES.has(branch)) return null;
  const lastSegment = branch.split("/").pop();
  const prefix = sanitizeForHostname(lastSegment);
  return prefix || null;
}
function detectWorktreePrefix(cwd = process.cwd()) {
  const cliResult = detectWorktreeViaCli(cwd);
  if (cliResult !== void 0) return cliResult;
  return detectWorktreeViaFilesystem(cwd);
}
function detectWorktreeViaCli(cwd) {
  try {
    const listOutput = execFileSync2("git", ["worktree", "list", "--porcelain"], {
      cwd,
      encoding: "utf-8",
      timeout: 5e3,
      stdio: ["ignore", "pipe", "ignore"]
    });
    const worktreeCount = listOutput.split("\n").filter((l) => l.startsWith("worktree ")).length;
    if (worktreeCount <= 1) return null;
    const gitDir = path2.resolve(
      cwd,
      execFileSync2("git", ["rev-parse", "--git-dir"], {
        cwd,
        encoding: "utf-8",
        timeout: 5e3,
        stdio: ["ignore", "pipe", "ignore"]
      }).trim()
    );
    const gitCommonDir = path2.resolve(
      cwd,
      execFileSync2("git", ["rev-parse", "--git-common-dir"], {
        cwd,
        encoding: "utf-8",
        timeout: 5e3,
        stdio: ["ignore", "pipe", "ignore"]
      }).trim()
    );
    if (gitDir === gitCommonDir) return null;
    const branch = execFileSync2("git", ["rev-parse", "--abbrev-ref", "HEAD"], {
      cwd,
      encoding: "utf-8",
      timeout: 5e3,
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
    const prefix = branchToPrefix(branch);
    if (!prefix) return null;
    return { prefix, source: "git branch" };
  } catch {
    return void 0;
  }
}
function detectWorktreeViaFilesystem(startDir) {
  let dir = startDir;
  for (; ; ) {
    const gitPath = path2.join(dir, ".git");
    try {
      const stat = fs2.statSync(gitPath);
      if (stat.isDirectory()) {
        return null;
      }
      if (stat.isFile()) {
        const content = fs2.readFileSync(gitPath, "utf-8").trim();
        const match = content.match(/^gitdir:\s*(.+)$/);
        if (!match) return null;
        const gitdir = match[1];
        if (!gitdir.match(/[/\\]worktrees[/\\][^/\\]+$/)) return null;
        const branch = readBranchFromHead(path2.resolve(dir, gitdir));
        const prefix = branchToPrefix(branch ?? "");
        if (!prefix) return null;
        return { prefix, source: "git branch" };
      }
    } catch {
    }
    const parent = path2.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}
function readBranchFromHead(gitdir) {
  try {
    const head = fs2.readFileSync(path2.join(gitdir, "HEAD"), "utf-8").trim();
    const refMatch = head.match(/^ref: refs\/heads\/(.+)$/);
    return refMatch ? refMatch[1] : null;
  } catch {
    return null;
  }
}

// src/cli-utils.ts
import * as fs3 from "fs";
import * as http from "http";
import * as https from "https";
import * as net from "net";
import * as os from "os";
import * as path3 from "path";
import * as readline from "readline";
import { execSync, spawn } from "child_process";
var isWindows = process.platform === "win32";
var FALLBACK_PROXY_PORT = 1355;
var PRIVILEGED_PORT_THRESHOLD = 1024;
var INTERNAL_LAN_IP_ENV = "PORTLESS_INTERNAL_LAN_IP";
var INTERNAL_LAN_IP_FLAG = "--lan-ip-auto";
var LEGACY_SYSTEM_STATE_DIR = isWindows ? path3.join(os.tmpdir(), "portless") : "/tmp/portless";
var USER_STATE_DIR = path3.join(os.homedir(), ".portless");
var MIN_APP_PORT = 4e3;
var MAX_APP_PORT = 4999;
var RANDOM_PORT_ATTEMPTS = 50;
var BLOCKED_PORTS = /* @__PURE__ */ new Set([
  0,
  1,
  7,
  9,
  11,
  13,
  15,
  17,
  19,
  20,
  21,
  22,
  23,
  25,
  37,
  42,
  43,
  53,
  69,
  77,
  79,
  87,
  95,
  101,
  102,
  103,
  104,
  109,
  110,
  111,
  113,
  115,
  117,
  119,
  123,
  135,
  137,
  139,
  143,
  161,
  179,
  389,
  427,
  465,
  512,
  513,
  514,
  515,
  526,
  530,
  531,
  532,
  540,
  548,
  554,
  556,
  563,
  587,
  601,
  636,
  989,
  990,
  993,
  995,
  1719,
  1720,
  1723,
  2049,
  3659,
  4045,
  4190,
  5060,
  5061,
  6e3,
  6566,
  6665,
  6666,
  6667,
  6668,
  6669,
  6679,
  6697,
  10080
]);
var SOCKET_TIMEOUT_MS = 500;
var PID_LOOKUP_TIMEOUT_MS = 5e3;
var WAIT_FOR_PROXY_MAX_ATTEMPTS = 20;
var WAIT_FOR_PROXY_INTERVAL_MS = 250;
var SIGNAL_CODES = {
  SIGHUP: 1,
  SIGINT: 2,
  SIGQUIT: 3,
  SIGABRT: 6,
  SIGKILL: 9,
  SIGTERM: 15
};
function killTree(child, signal = "SIGTERM") {
  if (!child.pid) {
    child.kill(signal);
    return;
  }
  if (!isWindows) {
    try {
      process.kill(-child.pid, signal);
      return;
    } catch {
    }
  }
  try {
    child.kill(signal);
  } catch {
  }
}
function getProtocolPort(tls2) {
  return tls2 ? 443 : 80;
}
function getDefaultPort(tls2) {
  const envPort = process.env.PORTLESS_PORT;
  if (envPort) {
    const port = parseInt(envPort, 10);
    if (!isNaN(port) && port >= 1 && port <= 65535) return port;
  }
  return tls2 === void 0 ? FALLBACK_PROXY_PORT : getProtocolPort(tls2);
}
function resolveStateDir(_port) {
  if (process.env.PORTLESS_STATE_DIR) return process.env.PORTLESS_STATE_DIR;
  return USER_STATE_DIR;
}
function readPortFromDir(dir) {
  try {
    const raw = fs3.readFileSync(path3.join(dir, "proxy.port"), "utf-8").trim();
    const port = parseInt(raw, 10);
    return isNaN(port) ? null : port;
  } catch {
    return null;
  }
}
var TLS_MARKER_FILE = "proxy.tls";
function readTlsMarker(dir) {
  try {
    return fs3.existsSync(path3.join(dir, TLS_MARKER_FILE));
  } catch {
    return false;
  }
}
function writeTlsMarker(dir, enabled2) {
  const markerPath = path3.join(dir, TLS_MARKER_FILE);
  if (enabled2) {
    fs3.writeFileSync(markerPath, "1", { mode: 420 });
  } else {
    try {
      fs3.unlinkSync(markerPath);
    } catch {
    }
  }
}
var LAN_MARKER_FILE = "proxy.lan";
function readLanMarker(dir) {
  try {
    const raw = fs3.readFileSync(path3.join(dir, LAN_MARKER_FILE), "utf-8").trim();
    return raw || null;
  } catch {
    return null;
  }
}
function writeLanMarker(dir, ip) {
  const markerPath = path3.join(dir, LAN_MARKER_FILE);
  if (!ip) {
    try {
      fs3.unlinkSync(markerPath);
    } catch {
    }
  } else {
    fs3.writeFileSync(markerPath, ip, { mode: 420 });
  }
}
var DEFAULT_TLD = "localhost";
var RISKY_TLDS = /* @__PURE__ */ new Map([
  ["local", "conflicts with mDNS/Bonjour on macOS"],
  ["dev", "Google-owned; browsers force HTTPS via preloaded HSTS"],
  ["com", "public TLD; DNS requests will leak to the internet"],
  ["org", "public TLD; DNS requests will leak to the internet"],
  ["net", "public TLD; DNS requests will leak to the internet"],
  ["io", "public TLD; DNS requests will leak to the internet"],
  ["app", "public TLD; DNS requests will leak to the internet"],
  ["edu", "public TLD; DNS requests will leak to the internet"],
  ["gov", "public TLD; DNS requests will leak to the internet"],
  ["mil", "public TLD; DNS requests will leak to the internet"],
  ["int", "public TLD; DNS requests will leak to the internet"]
]);
function validateTld(tld) {
  if (!tld) return "TLD cannot be empty";
  if (!/^[a-z0-9]+$/.test(tld)) {
    return `Invalid TLD "${tld}": must contain only lowercase letters and digits`;
  }
  return null;
}
var TLD_FILE = "proxy.tld";
function readTldFromDir(dir) {
  try {
    const raw = fs3.readFileSync(path3.join(dir, TLD_FILE), "utf-8").trim();
    return raw || DEFAULT_TLD;
  } catch {
    return DEFAULT_TLD;
  }
}
function writeTldFile(dir, tld) {
  const filePath = path3.join(dir, TLD_FILE);
  if (tld === DEFAULT_TLD) {
    try {
      fs3.unlinkSync(filePath);
    } catch {
    }
  } else {
    fs3.writeFileSync(filePath, tld, { mode: 420 });
  }
}
function getDefaultTld() {
  const val = process.env.PORTLESS_TLD?.trim().toLowerCase();
  if (!val) return DEFAULT_TLD;
  const err = validateTld(val);
  if (err) throw new Error(`PORTLESS_TLD: ${err}`);
  return val;
}
function isHttpsEnvDisabled() {
  const val = process.env.PORTLESS_HTTPS;
  return val === "0" || val === "false";
}
function isWildcardEnvEnabled() {
  const val = process.env.PORTLESS_WILDCARD;
  return val === "1" || val === "true";
}
function isLanEnvEnabled() {
  const val = process.env.PORTLESS_LAN;
  return val === "1" || val === "true";
}
function readPersistedProxyState() {
  const dir = process.env.PORTLESS_STATE_DIR || USER_STATE_DIR;
  const port = readPortFromDir(dir);
  if (port !== null) {
    const tls2 = readTlsMarker(dir);
    const tld = readTldFromDir(dir);
    const lanIp = readLanMarker(dir);
    return { port, tls: tls2, tld, lanMode: lanIp !== null || tld === "local" };
  }
  return null;
}
function buildProxyStartConfig(options) {
  const effectiveTld = options.lanMode ? "local" : options.tld;
  const args = [];
  if (options.foreground) {
    args.push("--foreground");
  }
  if (options.includePort && options.proxyPort !== void 0) {
    args.push("--port", options.proxyPort.toString());
  }
  if (options.useHttps) {
    if (options.customCertPath && options.customKeyPath) {
      args.push("--cert", options.customCertPath, "--key", options.customKeyPath);
    } else {
      args.push("--https");
    }
  } else {
    args.push("--no-tls");
  }
  if (options.lanMode) {
    args.push("--lan");
    if (options.lanIp) {
      if (options.lanIpExplicit) {
        args.push("--ip", options.lanIp);
      } else {
        args.push(INTERNAL_LAN_IP_FLAG, options.lanIp);
      }
    }
  } else if (effectiveTld !== DEFAULT_TLD) {
    args.push("--tld", effectiveTld);
  }
  if (options.useWildcard) {
    args.push("--wildcard");
  }
  if (options.skipTrust) {
    args.push("--skip-trust");
  }
  return { effectiveTld, args };
}
async function discoverState() {
  if (process.env.PORTLESS_STATE_DIR) {
    const dir2 = process.env.PORTLESS_STATE_DIR;
    const port = readPortFromDir(dir2) ?? getDefaultPort();
    const lanIp = readLanMarker(dir2);
    if (await isProxyRunning(port) || await isPortListening(port)) {
      const tls2 = readTlsMarker(dir2);
      const tld = readTldFromDir(dir2);
      return { dir: dir2, port, tls: tls2, tld, lanMode: lanIp !== null || tld === "local", lanIp };
    }
    return {
      dir: dir2,
      port,
      tls: readTlsMarker(dir2),
      tld: readTldFromDir(dir2),
      lanMode: lanIp !== null,
      lanIp: null
    };
  }
  const userPort = readPortFromDir(USER_STATE_DIR);
  if (userPort !== null) {
    if (await isProxyRunning(userPort)) {
      const tls2 = readTlsMarker(USER_STATE_DIR);
      const tld = readTldFromDir(USER_STATE_DIR);
      const lanIp = readLanMarker(USER_STATE_DIR);
      return {
        dir: USER_STATE_DIR,
        port: userPort,
        tls: tls2,
        tld,
        lanMode: lanIp !== null || tld === "local",
        lanIp
      };
    }
  }
  const legacyPort = readPortFromDir(LEGACY_SYSTEM_STATE_DIR);
  if (legacyPort !== null) {
    if (await isProxyRunning(legacyPort)) {
      const tls2 = readTlsMarker(LEGACY_SYSTEM_STATE_DIR);
      const tld = readTldFromDir(LEGACY_SYSTEM_STATE_DIR);
      const lanIp = readLanMarker(LEGACY_SYSTEM_STATE_DIR);
      return {
        dir: LEGACY_SYSTEM_STATE_DIR,
        port: legacyPort,
        tls: tls2,
        tld,
        lanMode: lanIp !== null || tld === "local",
        lanIp
      };
    }
  }
  const configuredPort = getDefaultPort();
  const probePorts = /* @__PURE__ */ new Set([443, 80, FALLBACK_PROXY_PORT, configuredPort]);
  for (const port of probePorts) {
    if (await isProxyRunning(port)) {
      const dir2 = resolveStateDir(port);
      const markerTls = readTlsMarker(dir2);
      const tls2 = markerTls || port === getProtocolPort(true);
      const tld = readTldFromDir(dir2);
      const lanIp = readLanMarker(dir2);
      return { dir: dir2, port, tls: tls2, tld, lanMode: lanIp !== null || tld === "local", lanIp };
    }
  }
  const dir = resolveStateDir(configuredPort);
  return {
    dir,
    port: configuredPort,
    tls: readTlsMarker(dir),
    tld: readTldFromDir(dir),
    lanMode: readLanMarker(dir) !== null,
    lanIp: null
  };
}
async function findFreePort(minPort = MIN_APP_PORT, maxPort = MAX_APP_PORT) {
  if (minPort > maxPort) {
    throw new Error(`minPort (${minPort}) must be <= maxPort (${maxPort})`);
  }
  const tryPort = (port) => {
    return new Promise((resolve3) => {
      const server = net.createServer();
      server.listen(port, () => {
        server.close(() => resolve3(true));
      });
      server.on("error", () => resolve3(false));
    });
  };
  for (let i = 0; i < RANDOM_PORT_ATTEMPTS; i++) {
    const port = minPort + Math.floor(Math.random() * (maxPort - minPort + 1));
    if (!BLOCKED_PORTS.has(port) && await tryPort(port)) {
      return port;
    }
  }
  for (let port = minPort; port <= maxPort; port++) {
    if (!BLOCKED_PORTS.has(port) && await tryPort(port)) {
      return port;
    }
  }
  throw new Error(`No free port found in range ${minPort}-${maxPort}`);
}
function isProxyRunning(port, tls2 = false) {
  return new Promise((resolve3) => {
    const requestFn = tls2 ? https.request : http.request;
    const req = requestFn(
      {
        hostname: "127.0.0.1",
        port,
        path: "/",
        method: "HEAD",
        timeout: SOCKET_TIMEOUT_MS,
        ...tls2 ? { rejectUnauthorized: false } : {}
      },
      (res) => {
        res.resume();
        resolve3(res.headers[PORTLESS_HEADER.toLowerCase()] === "1");
      }
    );
    req.on("error", () => resolve3(false));
    req.on("timeout", () => {
      req.destroy();
      resolve3(false);
    });
    req.end();
  });
}
function isPortListening(port) {
  return new Promise((resolve3) => {
    const socket = net.createConnection({ host: "127.0.0.1", port });
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve3(result);
    };
    socket.setTimeout(SOCKET_TIMEOUT_MS);
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
    socket.once("timeout", () => finish(false));
  });
}
function parsePidFromNetstat(output, port) {
  for (const line of output.split(/\r?\n/)) {
    if (!line.includes("LISTENING")) continue;
    const parts = line.trim().split(/\s+/);
    if (parts.length < 5) continue;
    const localAddr = parts[1];
    const lastColon = localAddr.lastIndexOf(":");
    if (lastColon === -1) continue;
    const addrPort = parseInt(localAddr.substring(lastColon + 1), 10);
    if (addrPort === port) {
      const pid = parseInt(parts[parts.length - 1], 10);
      if (!isNaN(pid) && pid > 0) return pid;
    }
  }
  return null;
}
function findPidsOnPort(port) {
  try {
    if (isWindows) {
      const output2 = execSync("netstat -ano -p tcp", {
        encoding: "utf-8",
        timeout: PID_LOOKUP_TIMEOUT_MS
      });
      const pid = parsePidFromNetstat(output2, port);
      return pid === null ? [] : [pid];
    }
    const output = execSync(`lsof -ti tcp:${port} -sTCP:LISTEN`, {
      encoding: "utf-8",
      timeout: PID_LOOKUP_TIMEOUT_MS
    });
    return output.trim().split("\n").map((s) => parseInt(s, 10)).filter((n) => !isNaN(n) && n > 0);
  } catch {
    return [];
  }
}
function findPidOnPort(port) {
  try {
    if (isWindows) {
      const output2 = execSync("netstat -ano -p tcp", {
        encoding: "utf-8",
        timeout: PID_LOOKUP_TIMEOUT_MS
      });
      return parsePidFromNetstat(output2, port);
    }
    const output = execSync(`lsof -ti tcp:${port} -sTCP:LISTEN`, {
      encoding: "utf-8",
      timeout: PID_LOOKUP_TIMEOUT_MS
    });
    const pid = parseInt(output.trim().split("\n")[0], 10);
    return isNaN(pid) ? null : pid;
  } catch {
    return null;
  }
}
async function waitForProxy(port, maxAttempts = WAIT_FOR_PROXY_MAX_ATTEMPTS, intervalMs = WAIT_FOR_PROXY_INTERVAL_MS, tls2 = false) {
  for (let i = 0; i < maxAttempts; i++) {
    await new Promise((resolve3) => setTimeout(resolve3, intervalMs));
    if (await isProxyRunning(port, tls2)) {
      return true;
    }
  }
  return false;
}
function shellEscape(arg) {
  return `'${arg.replace(/'/g, "'\\''")}'`;
}
function collectBinPaths(cwd) {
  const dirs = [];
  let dir = cwd;
  for (; ; ) {
    const bin = path3.join(dir, "node_modules", ".bin");
    if (fs3.existsSync(bin)) {
      dirs.push(bin);
    }
    const parent = path3.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return dirs;
}
function augmentedPath(env, cwd) {
  const source = env ?? process.env;
  const base = source.PATH ?? source.Path ?? "";
  const bins = collectBinPaths(cwd ?? process.cwd());
  const nodeBin = path3.dirname(process.execPath);
  const allBins = [...bins, nodeBin];
  return allBins.join(path3.delimiter) + path3.delimiter + base;
}
function spawnCommand(commandArgs, options) {
  const env = {
    ...options?.env ?? process.env,
    PATH: augmentedPath(options?.env)
  };
  if (isWindows) {
    for (const key of Object.keys(env)) {
      if (key !== "PATH" && key.toUpperCase() === "PATH") {
        delete env[key];
      }
    }
  }
  const child = isWindows ? spawn("cmd.exe", ["/d", "/s", "/c", commandArgs.join(" ")], {
    stdio: "inherit",
    env
  }) : spawn("/bin/sh", ["-c", commandArgs.map(shellEscape).join(" ")], {
    stdio: "inherit",
    env,
    detached: true
  });
  let exiting = false;
  const cleanup = () => {
    process.removeListener("SIGINT", onSigInt);
    process.removeListener("SIGTERM", onSigTerm);
    options?.onCleanup?.();
  };
  const handleSignal = (signal) => {
    if (exiting) return;
    exiting = true;
    killTree(child, signal);
    cleanup();
    process.exit(128 + (SIGNAL_CODES[signal] || 15));
  };
  const onSigInt = () => handleSignal("SIGINT");
  const onSigTerm = () => handleSignal("SIGTERM");
  process.on("SIGINT", onSigInt);
  process.on("SIGTERM", onSigTerm);
  child.on("error", (err) => {
    if (exiting) return;
    exiting = true;
    console.error(`Failed to run command: ${err.message}`);
    if (err.code === "ENOENT") {
      console.error(`Is "${commandArgs[0]}" installed and in your PATH?`);
    }
    cleanup();
    process.exit(1);
  });
  child.on("exit", (code, signal) => {
    if (exiting) return;
    exiting = true;
    cleanup();
    if (signal) {
      process.exit(128 + (SIGNAL_CODES[signal] || 15));
    }
    process.exit(code ?? 1);
  });
}
var FRAMEWORKS_NEEDING_PORT = {
  vite: { strictPort: true },
  vp: { strictPort: true },
  "react-router": { strictPort: true },
  rsbuild: { strictPort: false },
  astro: { strictPort: false },
  ng: { strictPort: false },
  "react-native": { strictPort: false },
  expo: { strictPort: false }
};
var PACKAGE_RUNNERS = {
  npx: [],
  bunx: [],
  pnpx: [],
  yarn: ["dlx", "exec"],
  pnpm: ["dlx", "exec"]
};
function findFrameworkBasename(commandArgs) {
  if (commandArgs.length === 0) return null;
  const first = path3.basename(commandArgs[0]);
  if (FRAMEWORKS_NEEDING_PORT[first]) return first;
  const subcommands = PACKAGE_RUNNERS[first];
  if (!subcommands) return null;
  let i = 1;
  if (subcommands.length > 0) {
    while (i < commandArgs.length && commandArgs[i].startsWith("-")) i++;
    if (i >= commandArgs.length) return null;
    if (!subcommands.includes(commandArgs[i])) {
      const name2 = path3.basename(commandArgs[i]);
      return FRAMEWORKS_NEEDING_PORT[name2] ? name2 : null;
    }
    i++;
  }
  while (i < commandArgs.length && commandArgs[i].startsWith("-")) i++;
  if (i >= commandArgs.length) return null;
  const name = path3.basename(commandArgs[i]);
  return FRAMEWORKS_NEEDING_PORT[name] ? name : null;
}
function injectFrameworkFlags(commandArgs, port) {
  const basename5 = findFrameworkBasename(commandArgs);
  if (!basename5) return;
  const framework = FRAMEWORKS_NEEDING_PORT[basename5];
  if (!commandArgs.includes("--port")) {
    commandArgs.push("--port", port.toString());
    if (framework.strictPort) {
      commandArgs.push("--strictPort");
    }
  }
  if (!commandArgs.includes("--host")) {
    const isExpoLan = basename5 === "expo" && isLanEnvEnabled();
    if (isExpoLan) return;
    const hostValue = basename5 === "expo" ? "localhost" : "127.0.0.1";
    commandArgs.push("--host", hostValue);
  }
}

// src/clean-utils.ts
import * as fs4 from "fs";
import * as path4 from "path";
var PORTLESS_STATE_FILES = [
  "routes.json",
  "routes.lock",
  "proxy.pid",
  "proxy.port",
  "proxy.log",
  "proxy.tls",
  "proxy.tld",
  "proxy.lan",
  "ca-key.pem",
  "ca.pem",
  "server-key.pem",
  "server.pem",
  "server.csr",
  "server-ext.cnf",
  "ca.srl"
];
var HOST_CERTS_DIR2 = "host-certs";
function collectStateDirsForCleanup() {
  const dirs = /* @__PURE__ */ new Set();
  const add = (d) => {
    const trimmed = d?.trim();
    if (!trimmed) return;
    const resolved = path4.resolve(trimmed);
    if (fs4.existsSync(resolved)) dirs.add(resolved);
  };
  add(USER_STATE_DIR);
  add(LEGACY_SYSTEM_STATE_DIR);
  add(process.env.PORTLESS_STATE_DIR);
  return [...dirs];
}
function removePortlessStateFiles(dir) {
  for (const f of PORTLESS_STATE_FILES) {
    try {
      fs4.unlinkSync(path4.join(dir, f));
    } catch {
    }
  }
  try {
    fs4.rmSync(path4.join(dir, HOST_CERTS_DIR2), { recursive: true, force: true });
  } catch {
  }
}

// src/mdns.ts
import { spawn as spawn2, spawnSync as spawnSync2 } from "child_process";

// src/lan-ip.ts
import { createSocket } from "dgram";
import { networkInterfaces } from "os";
var PROBE_HOST = "1.1.1.1";
var PROBE_PORT = 53;
var NO_ROUTE_IP = "0.0.0.0";
function isIPv4Family(family) {
  return family === "IPv4" || family === 4;
}
function parseMac(macStr) {
  return macStr.split(":").slice(0, 16).map((seq) => parseInt(seq, 16));
}
function isInternalInterface(iname, macStr, internal) {
  if (internal) {
    return true;
  }
  const mac = parseMac(macStr);
  if (mac.every((x) => !x)) {
    return true;
  }
  if (mac[0] === 0 && mac[1] === 21 && mac[2] === 93) {
    return true;
  }
  if (iname.includes("vEthernet") || /^bridge\d+$/.test(iname)) {
    return true;
  }
  return false;
}
function probeDefaultRouteIPv4() {
  return new Promise((resolve3, reject) => {
    const socket = createSocket({ type: "udp4", reuseAddr: true });
    socket.on("error", (error) => {
      socket.close();
      socket.unref();
      reject(error);
    });
    socket.connect(PROBE_PORT, PROBE_HOST, () => {
      const addr = socket.address();
      socket.close();
      socket.unref();
      if (addr && "address" in addr && addr.address && addr.address !== NO_ROUTE_IP) {
        resolve3(addr.address);
      } else {
        reject(new Error("No route to host"));
      }
    });
  });
}
function findInterfaceRowForIp(ip) {
  const ifs = networkInterfaces();
  for (const iname of Object.keys(ifs)) {
    const entries = ifs[iname];
    if (!entries) continue;
    for (const e of entries) {
      if (!isIPv4Family(e.family)) continue;
      if (e.address !== ip) continue;
      return { iname, address: e.address, mac: e.mac, internal: e.internal };
    }
  }
  return null;
}
async function getLocalNetworkIp() {
  try {
    const ip = await probeDefaultRouteIPv4();
    if (ip === "127.0.0.1") {
      return null;
    }
    const row = findInterfaceRowForIp(ip);
    if (!row) {
      return null;
    }
    if (row.address === "127.0.0.1") {
      return null;
    }
    if (isInternalInterface(row.iname, row.mac, row.internal)) {
      return null;
    }
    return row.address;
  } catch {
    return null;
  }
}

// src/mdns.ts
var activePublishers = /* @__PURE__ */ new Map();
var LAN_IP_POLL_INTERVAL_MS = 5e3;
function getMdnsPublisher() {
  if (process.platform === "darwin") {
    return {
      command: "dns-sd",
      probeArgs: ["-h"],
      missingReason: "dns-sd not found",
      buildArgs: (fqdn, name, port, ip) => [
        "-P",
        name,
        "_http._tcp",
        "local",
        port.toString(),
        fqdn,
        ip
      ]
    };
  }
  if (process.platform === "linux") {
    return {
      command: "avahi-publish-address",
      probeArgs: ["--help"],
      missingReason: "avahi-publish-address not found. Install avahi-utils: sudo apt install avahi-utils",
      buildArgs: (fqdn, _name, _port, ip) => ["-R", fqdn, ip]
    };
  }
  return null;
}
function hasCommand(command, probeArgs) {
  const result = spawnSync2(command, probeArgs, {
    stdio: "ignore",
    timeout: 1e3,
    windowsHide: true
  });
  return result.error?.code !== "ENOENT";
}
function startLanIpMonitor(options) {
  const resolveIp = options.resolveIp ?? getLocalNetworkIp;
  let currentIp = options.initialIp;
  let stopped = false;
  let polling = false;
  const poll = async () => {
    if (stopped || polling) return;
    polling = true;
    try {
      const nextIp = await resolveIp();
      if (stopped || nextIp === currentIp) return;
      const previousIp = currentIp;
      currentIp = nextIp;
      options.onChange(nextIp, previousIp);
    } catch (error) {
      options.onError?.(error);
    } finally {
      polling = false;
    }
  };
  const timer = setInterval(() => {
    void poll();
  }, options.intervalMs ?? LAN_IP_POLL_INTERVAL_MS);
  timer.unref?.();
  return {
    stop: () => {
      stopped = true;
      clearInterval(timer);
    }
  };
}
function isMdnsSupported() {
  const publisher = getMdnsPublisher();
  if (!publisher) {
    return { supported: false, reason: "mDNS publishing is not supported on this platform" };
  }
  if (!hasCommand(publisher.command, publisher.probeArgs)) {
    return { supported: false, reason: publisher.missingReason };
  }
  return { supported: true };
}
function serviceName(hostname) {
  return hostname.replace(/\.local$/, "");
}
function publish(hostname, port, ip, onError) {
  if (activePublishers.has(hostname)) return;
  const fqdn = hostname.endsWith(".local") ? hostname : `${hostname}.local`;
  const name = serviceName(fqdn);
  const publisher = getMdnsPublisher();
  if (!publisher) {
    return;
  }
  const child = spawn2(publisher.command, publisher.buildArgs(fqdn, name, port, ip), {
    stdio: "ignore",
    detached: false
  });
  child.on("error", (err) => {
    activePublishers.delete(hostname);
    const msg = err.code === "ENOENT" ? publisher.missingReason : `mDNS publish error for ${hostname}: ${err.message}`;
    onError?.(msg);
  });
  child.on("exit", () => {
    activePublishers.delete(hostname);
  });
  activePublishers.set(hostname, child);
}
function unpublish(hostname) {
  const child = activePublishers.get(hostname);
  if (!child) return;
  activePublishers.delete(hostname);
  child.kill("SIGTERM");
}
function cleanupAll() {
  for (const child of activePublishers.values()) {
    child.kill("SIGTERM");
  }
  activePublishers.clear();
}

// src/config.ts
import * as fs5 from "fs";
import * as path5 from "path";
var ConfigValidationError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "ConfigValidationError";
  }
};
var CONFIG_FILENAME = "portless.json";
function loadConfig(cwd = process.cwd()) {
  const configPath = path5.join(cwd, CONFIG_FILENAME);
  try {
    const raw = fs5.readFileSync(configPath, "utf-8");
    const parsed = JSON.parse(raw);
    validateConfig(parsed, configPath);
    return { config: parsed, configDir: cwd };
  } catch (err) {
    if (isErrnoException2(err) && err.code === "ENOENT") {
      return loadConfigFromPackageJson(cwd);
    }
    if (err instanceof SyntaxError) {
      throw new ConfigValidationError(`Invalid JSON in ${configPath}`);
    }
    throw err;
  }
}
function normalizePortlessValue(value) {
  if (typeof value === "string") {
    return value.trim() ? { name: value.trim() } : null;
  }
  return value;
}
function loadConfigFromPackageJson(dir) {
  const pkgPath = path5.join(dir, "package.json");
  try {
    const raw = fs5.readFileSync(pkgPath, "utf-8");
    const pkg = JSON.parse(raw);
    if (pkg && typeof pkg === "object" && "portless" in pkg) {
      const config = normalizePortlessValue(pkg.portless);
      if (config === null) return null;
      validateConfig(config, `${pkgPath} "portless"`);
      return { config, configDir: dir };
    }
  } catch (err) {
    if (isErrnoException2(err) && err.code === "ENOENT") return null;
    if (err instanceof SyntaxError) return null;
    throw err;
  }
  return null;
}
function loadPackagePortlessConfig(dir) {
  const pkgPath = path5.join(dir, "package.json");
  try {
    const raw = fs5.readFileSync(pkgPath, "utf-8");
    const pkg = JSON.parse(raw);
    if (pkg && typeof pkg === "object" && "portless" in pkg) {
      const config = normalizePortlessValue(pkg.portless);
      if (config === null) return null;
      if (typeof config === "object" && !Array.isArray(config)) {
        validateAppConfig(config, "portless", pkgPath);
        return config;
      }
    }
  } catch (err) {
    if (err instanceof ConfigValidationError) throw err;
  }
  return null;
}
function resolveAppConfig(config, configDir, packageDir) {
  if (config.apps) {
    const rel = normalizePath(path5.relative(configDir, packageDir));
    if (rel && !rel.startsWith("..")) {
      let candidate = rel;
      while (candidate) {
        if (config.apps[candidate]) {
          return config.apps[candidate];
        }
        const parent = path5.dirname(candidate);
        if (parent === "." || parent === candidate) break;
        candidate = normalizePath(parent);
      }
    }
    return {};
  }
  return { name: config.name, script: config.script, appPort: config.appPort, proxy: config.proxy };
}
function hasScript(scriptName, dir) {
  const pkgPath = path5.join(dir, "package.json");
  try {
    const raw = fs5.readFileSync(pkgPath, "utf-8");
    const pkg = JSON.parse(raw);
    return typeof pkg?.scripts?.[scriptName] === "string";
  } catch {
    return false;
  }
}
var LOCK_FILES = [
  ["pnpm-lock.yaml", "pnpm"],
  ["yarn.lock", "yarn"],
  ["bun.lockb", "bun"],
  ["bun.lock", "bun"],
  ["package-lock.json", "npm"]
];
function detectPackageManager(cwd) {
  let dir = cwd;
  for (; ; ) {
    const pkgPath = path5.join(dir, "package.json");
    try {
      const raw = fs5.readFileSync(pkgPath, "utf-8");
      const pkg = JSON.parse(raw);
      if (typeof pkg.packageManager === "string") {
        const name = pkg.packageManager.split("@")[0];
        if (name === "pnpm" || name === "yarn" || name === "bun" || name === "npm") {
          return name;
        }
      }
    } catch {
    }
    for (const [file, pm] of LOCK_FILES) {
      try {
        fs5.accessSync(path5.join(dir, file), fs5.constants.F_OK);
        return pm;
      } catch {
      }
    }
    const parent = path5.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return "npm";
}
function resolveScriptCommand(scriptName, packageDir) {
  if (!hasScript(scriptName, packageDir)) return null;
  const pm = detectPackageManager(packageDir);
  return [pm, "run", scriptName];
}
function splitCommand(command) {
  const args = [];
  let current = "";
  let inSingle = false;
  let inDouble = false;
  let escaped = false;
  for (const ch of command) {
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (ch === "\\" && !inSingle) {
      escaped = true;
      continue;
    }
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
    } else if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
    } else if (/\s/.test(ch) && !inSingle && !inDouble) {
      if (current) {
        args.push(current);
        current = "";
      }
    } else {
      current += ch;
    }
  }
  if (current) args.push(current);
  return args;
}
var BUILD_ONLY_COMMANDS = /* @__PURE__ */ new Set([
  "tsup",
  "tsc",
  "esbuild",
  "rollup",
  "babel",
  "swc",
  "unbuild",
  "pkgroll",
  "ncc",
  "microbundle"
]);
function isServerCommand(args) {
  if (args.length === 0) return false;
  const bin = path5.basename(args[0]);
  return !BUILD_ONLY_COMMANDS.has(bin);
}
function normalizePath(p) {
  return p.replace(/\\/g, "/");
}
function isErrnoException2(err) {
  return err instanceof Error && "code" in err;
}
var KNOWN_TOP_KEYS = /* @__PURE__ */ new Set(["name", "script", "appPort", "proxy", "apps", "turbo"]);
var KNOWN_APP_KEYS = /* @__PURE__ */ new Set(["name", "script", "appPort", "proxy"]);
function validateConfig(config, configPath) {
  if (typeof config !== "object" || config === null || Array.isArray(config)) {
    throw new ConfigValidationError(`${configPath} must be a JSON object.`);
  }
  const obj = config;
  if (obj.name !== void 0) {
    if (typeof obj.name !== "string" || !obj.name.trim()) {
      throw new ConfigValidationError(`"name" in ${configPath} must be a non-empty string.`);
    }
  }
  if (obj.script !== void 0) {
    if (typeof obj.script !== "string" || !obj.script.trim()) {
      throw new ConfigValidationError(`"script" in ${configPath} must be a non-empty string.`);
    }
  }
  if (obj.appPort !== void 0) {
    if (typeof obj.appPort !== "number" || !Number.isInteger(obj.appPort) || obj.appPort < 1 || obj.appPort > 65535) {
      throw new ConfigValidationError(
        `"appPort" in ${configPath} must be an integer between 1 and 65535.`
      );
    }
  }
  if (obj.proxy !== void 0) {
    if (typeof obj.proxy !== "boolean") {
      throw new ConfigValidationError(`"proxy" in ${configPath} must be a boolean.`);
    }
  }
  if (obj.turbo !== void 0) {
    if (typeof obj.turbo !== "boolean") {
      throw new ConfigValidationError(`"turbo" in ${configPath} must be a boolean.`);
    }
  }
  if (obj.apps !== void 0) {
    if (typeof obj.apps !== "object" || obj.apps === null || Array.isArray(obj.apps)) {
      throw new ConfigValidationError(`"apps" in ${configPath} must be an object.`);
    }
    for (const [key, value] of Object.entries(obj.apps)) {
      if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new ConfigValidationError(`"apps.${key}" in ${configPath} must be an object.`);
      }
      validateAppConfig(value, `apps.${key}`, configPath);
    }
  }
  warnUnknownKeys(obj, KNOWN_TOP_KEYS, configPath);
}
function validateAppConfig(obj, prefix, configPath) {
  if (obj.name !== void 0) {
    if (typeof obj.name !== "string" || !obj.name.trim()) {
      throw new ConfigValidationError(
        `"${prefix}.name" in ${configPath} must be a non-empty string.`
      );
    }
  }
  if (obj.script !== void 0) {
    if (typeof obj.script !== "string" || !obj.script.trim()) {
      throw new ConfigValidationError(
        `"${prefix}.script" in ${configPath} must be a non-empty string.`
      );
    }
  }
  if (obj.appPort !== void 0) {
    if (typeof obj.appPort !== "number" || !Number.isInteger(obj.appPort) || obj.appPort < 1 || obj.appPort > 65535) {
      throw new ConfigValidationError(
        `"${prefix}.appPort" in ${configPath} must be an integer between 1 and 65535.`
      );
    }
  }
  if (obj.proxy !== void 0) {
    if (typeof obj.proxy !== "boolean") {
      throw new ConfigValidationError(`"${prefix}.proxy" in ${configPath} must be a boolean.`);
    }
  }
  warnUnknownKeys(obj, KNOWN_APP_KEYS, configPath, prefix);
}
function warnUnknownKeys(obj, known, configPath, prefix) {
  for (const key of Object.keys(obj)) {
    if (!known.has(key)) {
      const label = prefix ? `"${prefix}.${key}"` : `"${key}"`;
      console.warn(
        `Warning: Unknown key ${label} in ${configPath}. Known keys: ${[...known].join(", ")}`
      );
    }
  }
}

// src/workspace.ts
import * as fs6 from "fs";
import * as path6 from "path";
function findWorkspaceRoot(cwd = process.cwd()) {
  let dir = cwd;
  for (; ; ) {
    try {
      fs6.accessSync(path6.join(dir, "pnpm-workspace.yaml"), fs6.constants.R_OK);
      return dir;
    } catch {
    }
    if (readWorkspacesFromPackageJson(dir) !== null) {
      return dir;
    }
    const parent = path6.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}
function detectWorkspaceSource(workspaceRoot) {
  try {
    fs6.accessSync(path6.join(workspaceRoot, "pnpm-workspace.yaml"), fs6.constants.R_OK);
    return "pnpm";
  } catch {
  }
  if (readWorkspacesFromPackageJson(workspaceRoot) !== null) {
    return "package-json";
  }
  return null;
}
function readWorkspacesFromPackageJson(dir) {
  const pkgPath = path6.join(dir, "package.json");
  try {
    const raw = fs6.readFileSync(pkgPath, "utf-8");
    const pkg = JSON.parse(raw);
    if (!pkg || typeof pkg !== "object") return null;
    const ws = pkg.workspaces;
    if (Array.isArray(ws)) {
      return ws.filter((g) => typeof g === "string");
    }
    if (ws && typeof ws === "object" && !Array.isArray(ws) && Array.isArray(ws.packages)) {
      return ws.packages.filter((g) => typeof g === "string");
    }
  } catch {
  }
  return null;
}
function discoverWorkspacePackages(workspaceRoot) {
  const source = detectWorkspaceSource(workspaceRoot);
  let globs;
  if (source === "pnpm") {
    const wsPath = path6.join(workspaceRoot, "pnpm-workspace.yaml");
    let content;
    try {
      content = fs6.readFileSync(wsPath, "utf-8");
    } catch {
      return [];
    }
    globs = parsePnpmWorkspaceYaml(content);
  } else if (source === "package-json") {
    globs = readWorkspacesFromPackageJson(workspaceRoot) ?? [];
  } else {
    return [];
  }
  const dirs = expandPackageGlobs(workspaceRoot, globs);
  const packages = [];
  for (const dir of dirs) {
    const pkgPath = path6.join(dir, "package.json");
    try {
      const raw = fs6.readFileSync(pkgPath, "utf-8");
      const pkg = JSON.parse(raw);
      const rawName = typeof pkg.name === "string" ? pkg.name : null;
      const scopeMatch = rawName?.match(/^@([^/]+)\//);
      const scope = scopeMatch ? scopeMatch[1] : null;
      const name = rawName ? rawName.replace(/^@[^/]+\//, "") : null;
      const scripts = typeof pkg.scripts === "object" && pkg.scripts !== null ? pkg.scripts : {};
      packages.push({ dir, name, scope, scripts });
    } catch {
    }
  }
  return packages;
}
function parsePnpmWorkspaceYaml(content) {
  const lines = content.split("\n");
  const globs = [];
  let inPackages = false;
  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    const headerMatch = line.match(/^packages\s*:(.*)/);
    if (headerMatch) {
      const rest = headerMatch[1].trim();
      if (rest.startsWith("[")) {
        return parseFlowSequence(rest);
      }
      inPackages = true;
      continue;
    }
    if (inPackages) {
      if (line.length > 0 && !line.startsWith(" ") && !line.startsWith("	") && !line.startsWith("-")) {
        break;
      }
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const match = trimmed.match(/^-\s+['"]?([^'"#]+?)['"]?\s*(?:#.*)?$/);
      if (match) {
        const glob = match[1].trim();
        if (glob) globs.push(glob);
      }
    }
  }
  return globs;
}
function parseFlowSequence(input) {
  const inner = input.replace(/^\[/, "").replace(/]\s*$/, "");
  return inner.split(",").map((s) => s.trim().replace(/^['"]/, "").replace(/['"]$/, "").trim()).filter(Boolean);
}
function expandPackageGlobs(root, globs) {
  const included = /* @__PURE__ */ new Set();
  const excluded = /* @__PURE__ */ new Set();
  for (const glob of globs) {
    if (glob.startsWith("!")) {
      const negated = glob.slice(1);
      for (const dir of expandSingleGlob(root, negated)) {
        excluded.add(dir);
      }
    } else {
      for (const dir of expandSingleGlob(root, glob)) {
        included.add(dir);
      }
    }
  }
  for (const dir of excluded) {
    included.delete(dir);
  }
  return [...included].sort();
}
function segmentMatches(pattern, name) {
  if (pattern === "*" || pattern === "**") return true;
  const starIdx = pattern.indexOf("*");
  if (starIdx === -1) return pattern === name;
  const prefix = pattern.slice(0, starIdx);
  const suffix = pattern.slice(starIdx + 1).replace(/\*+$/, "");
  return name.startsWith(prefix) && name.endsWith(suffix);
}
function expandSingleGlob(root, glob) {
  const segments = glob.split("/");
  return expandSegments(root, segments);
}
function expandSegments(base, segments) {
  if (segments.length === 0) {
    try {
      const stat = fs6.statSync(base);
      if (stat.isDirectory()) return [base];
    } catch {
    }
    return [];
  }
  const [current, ...rest] = segments;
  if (current.includes("*")) {
    try {
      const entries = fs6.readdirSync(base, { withFileTypes: true });
      const matched = entries.filter((e) => e.isDirectory() && segmentMatches(current, e.name));
      if (rest.length === 0) {
        return matched.map((e) => path6.join(base, e.name));
      }
      const results = [];
      for (const entry of matched) {
        results.push(...expandSegments(path6.join(base, entry.name), rest));
      }
      return results;
    } catch {
      return [];
    }
  }
  return expandSegments(path6.join(base, current), rest);
}

// src/turbo.ts
import * as fs7 from "fs";
import * as path7 from "path";
var LOADER_FILENAME = "turbo-env-loader.cjs";
var MANIFEST_FILENAME = "dev-manifest.json";
function loaderPath(baseDir = USER_STATE_DIR) {
  return path7.join(baseDir, LOADER_FILENAME);
}
function manifestPath(baseDir = USER_STATE_DIR) {
  return path7.join(baseDir, MANIFEST_FILENAME);
}
function loaderSource(baseDir = USER_STATE_DIR) {
  return `"use strict";
var fs = require("fs");
var path = require("path");
var manifestPath = path.join(${JSON.stringify(baseDir)}, "dev-manifest.json");
try {
  var raw = fs.readFileSync(manifestPath, "utf-8");
  var manifest = JSON.parse(raw);
  var cwd = process.cwd();
  var entry = manifest[cwd];
  if (entry && typeof entry === "object") {
    var keys = Object.keys(entry);
    for (var i = 0; i < keys.length; i++) {
      process.env[keys[i]] = entry[keys[i]];
    }
  }
} catch (_) {}
`;
}
function ensureEnvLoader(baseDir = USER_STATE_DIR) {
  fs7.mkdirSync(baseDir, { recursive: true, mode: 493 });
  const target = loaderPath(baseDir);
  const source = loaderSource(baseDir);
  try {
    const existing = fs7.readFileSync(target, "utf-8");
    if (existing === source) return;
  } catch {
  }
  fs7.writeFileSync(target, source, { mode: 420 });
}
function writeManifest(entries, baseDir = USER_STATE_DIR) {
  fs7.mkdirSync(baseDir, { recursive: true, mode: 493 });
  fs7.writeFileSync(manifestPath(baseDir), JSON.stringify(entries, null, 2) + "\n", { mode: 420 });
}
function removeManifest(baseDir = USER_STATE_DIR) {
  try {
    fs7.unlinkSync(manifestPath(baseDir));
  } catch {
  }
}
function buildNodeOptions(baseDir = USER_STATE_DIR) {
  const existing = process.env.NODE_OPTIONS || "";
  const lp = loaderPath(baseDir);
  const requireFlag = lp.includes(" ") ? `--require "${lp}"` : `--require ${lp}`;
  return existing ? `${requireFlag} ${existing}` : requireFlag;
}
function hasTurboConfig(wsRoot) {
  try {
    fs7.accessSync(path7.join(wsRoot, "turbo.json"), fs7.constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

// src/cli.ts
var chalk = colors_default;
var HOSTS_DISPLAY = isWindows ? "hosts file" : "/etc/hosts";
var DEBOUNCE_MS = 100;
var POLL_INTERVAL_MS = 1e3;
var EXIT_TIMEOUT_MS = 2e3;
var SUDO_SPAWN_TIMEOUT_MS = 3e4;
function defaultProxyConfig(tld, useHttps, lanMode) {
  return {
    useHttps,
    customCertPath: null,
    customKeyPath: null,
    lanMode,
    lanIp: null,
    lanIpExplicit: false,
    tld: lanMode ? "local" : tld,
    useWildcard: false
  };
}
function resolveProxyConfig(options) {
  const config = defaultProxyConfig(
    options.defaultTld,
    options.useHttps,
    options.explicit.lanMode ? options.lanMode : options.persistedLanMode
  );
  if (options.explicit.useHttps) {
    config.useHttps = options.useHttps;
    if (!options.useHttps) {
      config.customCertPath = null;
      config.customKeyPath = null;
    }
  }
  if (options.explicit.customCert) {
    config.useHttps = true;
    config.customCertPath = options.customCertPath;
    config.customKeyPath = options.customKeyPath;
  }
  if (options.explicit.lanMode) {
    config.lanMode = options.lanMode;
    if (!options.lanMode) {
      config.lanIp = null;
      config.lanIpExplicit = false;
      if (!options.explicit.tld) {
        config.tld = options.defaultTld;
      }
    }
  }
  if (options.explicit.lanIp && options.lanIp) {
    config.lanMode = true;
    config.lanIp = options.lanIp;
    config.lanIpExplicit = true;
  }
  if (options.explicit.tld) {
    config.tld = options.tld;
  }
  if (options.explicit.useWildcard) {
    config.useWildcard = options.useWildcard;
  }
  if (!config.lanMode) {
    config.lanIp = null;
    config.lanIpExplicit = false;
  }
  if (config.lanMode) {
    config.tld = "local";
    if (!config.lanIpExplicit) {
      config.lanIp = null;
    }
  }
  if (!config.useHttps) {
    config.customCertPath = null;
    config.customKeyPath = null;
  }
  return config;
}
function readCurrentProxyConfig(dir) {
  const lanIp = readLanMarker(dir);
  const tld = readTldFromDir(dir);
  return {
    useHttps: readTlsMarker(dir),
    customCertPath: null,
    customKeyPath: null,
    lanMode: lanIp !== null || tld === "local",
    lanIp,
    lanIpExplicit: false,
    tld,
    useWildcard: false
  };
}
function getProxyConfigMismatchMessages(desiredConfig, actualConfig, explicit) {
  const messages = [];
  if (explicit.lanMode && desiredConfig.lanMode !== actualConfig.lanMode) {
    messages.push(
      desiredConfig.lanMode ? "requested LAN mode, but the running proxy is not using LAN mode" : "requested non-LAN mode, but the running proxy is using LAN mode"
    );
  }
  if (explicit.lanIp && desiredConfig.lanIp !== actualConfig.lanIp) {
    messages.push(
      `requested LAN IP ${desiredConfig.lanIp}, but the running proxy is using ${actualConfig.lanIp ?? "auto-detected LAN mode"}`
    );
  }
  if (explicit.useHttps && desiredConfig.useHttps !== actualConfig.useHttps) {
    messages.push(
      desiredConfig.useHttps ? "requested HTTPS, but the running proxy is using HTTP" : "requested HTTP, but the running proxy is using HTTPS"
    );
  }
  if (explicit.tld && desiredConfig.tld !== actualConfig.tld) {
    messages.push(
      `requested .${desiredConfig.tld}, but the running proxy is using .${actualConfig.tld}`
    );
  }
  return messages;
}
function formatProxyStartCommand(proxyPort, config) {
  const needsSudo = !isWindows && proxyPort < PRIVILEGED_PORT_THRESHOLD;
  const { args } = buildProxyStartConfig({
    useHttps: config.useHttps,
    customCertPath: config.customCertPath,
    customKeyPath: config.customKeyPath,
    lanMode: config.lanMode,
    lanIp: config.lanIpExplicit ? config.lanIp : null,
    lanIpExplicit: config.lanIpExplicit,
    tld: config.tld,
    useWildcard: config.useWildcard,
    includePort: proxyPort !== getDefaultPort(config.useHttps),
    proxyPort
  });
  return `${needsSudo ? "sudo " : ""}portless proxy start${args.length > 0 ? ` ${args.join(" ")}` : ""}`;
}
function printProxyConfigMismatch(proxyPort, desiredConfig, messages) {
  const needsSudo = !isWindows && proxyPort < PRIVILEGED_PORT_THRESHOLD;
  const portFlag = proxyPort !== getDefaultPort(desiredConfig.useHttps) ? ` -p ${proxyPort}` : "";
  console.error(
    chalk.yellow(`Proxy is already running on port ${proxyPort} with a different config.`)
  );
  for (const message of messages) {
    console.error(chalk.yellow(`- ${message}`));
  }
  console.error(chalk.blue("Stop it first, then restart with the desired settings:"));
  console.error(chalk.cyan(`  ${needsSudo ? "sudo " : ""}portless proxy stop${portFlag}`));
  console.error(chalk.cyan(`  ${formatProxyStartCommand(proxyPort, desiredConfig)}`));
  process.exit(1);
}
function getEntryScript() {
  const script = process.argv[1];
  if (!script) {
    throw new Error("Cannot determine portless entry script (process.argv[1] is undefined)");
  }
  return script;
}
function isLocallyInstalled() {
  let dir = process.cwd();
  for (; ; ) {
    if (fs8.existsSync(path8.join(dir, "node_modules", "portless", "package.json"))) {
      return true;
    }
    const parent = path8.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return false;
}
function collectPortlessEnvArgs() {
  const envArgs = [];
  for (const key of Object.keys(process.env)) {
    if (key.startsWith("PORTLESS_") && process.env[key]) {
      envArgs.push(`${key}=${process.env[key]}`);
    }
  }
  return envArgs;
}
function sudoStop(port) {
  const stopArgs = [process.execPath, getEntryScript(), "proxy", "stop", "-p", String(port)];
  console.log(colors_default.yellow("Proxy is running as root. Elevating with sudo to stop it..."));
  const result = spawnSync3("sudo", ["env", ...collectPortlessEnvArgs(), ...stopArgs], {
    stdio: "inherit",
    timeout: SUDO_SPAWN_TIMEOUT_MS
  });
  return result.status === 0;
}
function startProxyServer(store, proxyPort, tld, tlsOptions, lanIp, strict) {
  store.ensureDir();
  const isTls = !!tlsOptions;
  const mdnsSupport = isMdnsSupported();
  let activeLanIp = lanIp && mdnsSupport.supported ? lanIp : null;
  const lanIpPinned = !!process.env.PORTLESS_LAN_IP;
  let lanMonitor = null;
  if (lanIp && !mdnsSupport.supported) {
    const reason = mdnsSupport.reason ?? "mDNS publishing is not supported on this platform.";
    console.warn(chalk.yellow(`LAN mode disabled: ${reason}`));
  }
  const routesPath = store.getRoutesPath();
  if (!fs8.existsSync(routesPath)) {
    fs8.writeFileSync(routesPath, "[]", { mode: FILE_MODE });
  }
  try {
    fs8.chmodSync(routesPath, FILE_MODE);
  } catch {
  }
  fixOwnership(routesPath);
  let cachedRoutes = store.loadRoutes();
  let debounceTimer = null;
  let watcher = null;
  let pollingInterval = null;
  const routeFileVersion = () => {
    try {
      const stat = fs8.statSync(routesPath);
      return `${stat.ino}:${stat.mtimeMs}:${stat.size}`;
    } catch {
      return "missing";
    }
  };
  let lastRouteFileVersion = routeFileVersion();
  const autoSyncHosts = shouldAutoSyncHosts(process.env.PORTLESS_SYNC_HOSTS);
  const onMdnsError = (msg) => console.warn(chalk.yellow(msg));
  const publishCachedRoutes = () => {
    if (!activeLanIp) return;
    for (const route of cachedRoutes) {
      publish(route.hostname, proxyPort, activeLanIp, onMdnsError);
    }
  };
  const updateLanIp = (nextIp, previousIp = activeLanIp) => {
    if (nextIp === activeLanIp) return;
    if (activeLanIp) {
      cleanupAll();
    }
    activeLanIp = nextIp;
    writeLanMarker(store.dir, activeLanIp);
    if (previousIp && nextIp) {
      console.log(chalk.green(`LAN IP changed: ${previousIp} -> ${nextIp}`));
    } else if (previousIp && !nextIp) {
      console.warn(chalk.yellow("LAN mode temporarily unavailable: no active LAN IP"));
    } else if (!previousIp && nextIp) {
      console.log(chalk.green(`LAN mode restored: ${nextIp}`));
    }
    publishCachedRoutes();
  };
  const reloadRoutes = () => {
    try {
      const previousRoutes = new Map(cachedRoutes.map((r) => [r.hostname, r.port]));
      cachedRoutes = store.loadRoutes();
      lastRouteFileVersion = routeFileVersion();
      if (autoSyncHosts) {
        syncHostsFile(cachedRoutes.map((r) => r.hostname));
      }
      if (activeLanIp) {
        const currentRoutes = new Map(cachedRoutes.map((r) => [r.hostname, r.port]));
        for (const route of cachedRoutes) {
          const previousPort = previousRoutes.get(route.hostname);
          if (previousPort === void 0) {
            publish(route.hostname, proxyPort, activeLanIp, onMdnsError);
          } else if (previousPort !== route.port) {
            unpublish(route.hostname);
            publish(route.hostname, proxyPort, activeLanIp, onMdnsError);
          }
        }
        for (const hostname of previousRoutes.keys()) {
          if (!currentRoutes.has(hostname)) {
            unpublish(hostname);
          }
        }
      }
    } catch {
    }
  };
  try {
    const routesDir = path8.dirname(routesPath);
    const routesFilename = path8.basename(routesPath);
    watcher = fs8.watch(routesDir, (_eventType, filename) => {
      if (filename && filename.toString() !== routesFilename) return;
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(reloadRoutes, DEBOUNCE_MS);
    });
  } catch {
    console.warn(
      colors_default.yellow("Directory watching unavailable; falling back to polling for route changes")
    );
  }
  pollingInterval = setInterval(() => {
    if (routeFileVersion() !== lastRouteFileVersion) reloadRoutes();
  }, POLL_INTERVAL_MS);
  if (autoSyncHosts) {
    syncHostsFile(cachedRoutes.map((r) => r.hostname));
  }
  publishCachedRoutes();
  const server = createProxyServer({
    getRoutes: () => cachedRoutes,
    proxyPort,
    tld,
    strict,
    onError: (msg) => console.error(colors_default.red(msg)),
    tls: tlsOptions
  });
  server.on("error", (err) => {
    if (err.code === "EADDRINUSE") {
      console.error(colors_default.red(`Port ${proxyPort} is already in use.`));
      console.error(colors_default.blue("Stop the existing proxy first:"));
      console.error(colors_default.cyan("  portless proxy stop"));
      console.error(colors_default.blue("Or check what is using the port:"));
      console.error(
        colors_default.cyan(
          isWindows ? `  netstat -ano | findstr :${proxyPort}` : `  lsof -ti tcp:${proxyPort}`
        )
      );
    } else if (err.code === "EACCES") {
      console.error(colors_default.red(`Permission denied for port ${proxyPort}.`));
      console.error(colors_default.blue("Use an unprivileged port (no sudo needed):"));
      console.error(colors_default.cyan("  portless proxy start -p 1355"));
    } else {
      console.error(colors_default.red(`Proxy error: ${err.message}`));
    }
    if (redirectServer) redirectServer.close();
    process.exit(1);
  });
  let redirectServer = null;
  if (isTls && proxyPort !== 80) {
    redirectServer = createHttpRedirectServer(proxyPort);
    redirectServer.on("error", () => {
      redirectServer = null;
    });
    redirectServer.listen(80);
  }
  server.listen(proxyPort, () => {
    fs8.writeFileSync(store.pidPath, process.pid.toString(), { mode: FILE_MODE });
    fs8.writeFileSync(store.portFilePath, proxyPort.toString(), { mode: FILE_MODE });
    writeTlsMarker(store.dir, isTls);
    writeTldFile(store.dir, tld);
    writeLanMarker(store.dir, activeLanIp);
    fixOwnership(store.dir, store.pidPath, store.portFilePath);
    const proto = isTls ? "HTTPS/2" : "HTTP";
    const tldLabel = tld !== DEFAULT_TLD ? ` (TLD: .${tld})` : "";
    const modeLabel = strict === false ? " (wildcard)" : "";
    console.log(
      colors_default.green(`${proto} proxy listening on port ${proxyPort}${tldLabel}${modeLabel}`)
    );
    if (activeLanIp) {
      console.log(chalk.green(`LAN mode: ${activeLanIp}`));
      console.log(chalk.gray("Services are discoverable as <name>.local on your network"));
      if (isTls) {
        console.log(chalk.yellow("For HTTPS on devices, install the CA certificate:"));
        console.log(chalk.gray(`  ${path8.join(store.dir, "ca.pem")}`));
      }
      if (!lanIpPinned) {
        lanMonitor = startLanIpMonitor({
          initialIp: activeLanIp,
          onChange: (nextIp, previousIp) => updateLanIp(nextIp, previousIp),
          onError: (error) => {
            const message = error instanceof Error ? error.message : String(error);
            console.warn(chalk.yellow(`Failed to refresh LAN IP: ${message}`));
          }
        });
      }
    }
    if (redirectServer) {
      console.log(colors_default.green("HTTP-to-HTTPS redirect listening on port 80"));
    }
  });
  let exiting = false;
  const cleanup = () => {
    if (exiting) return;
    exiting = true;
    if (debounceTimer) clearTimeout(debounceTimer);
    if (pollingInterval) clearInterval(pollingInterval);
    if (lanMonitor) lanMonitor.stop();
    if (watcher) {
      watcher.close();
    }
    if (activeLanIp) cleanupAll();
    if (redirectServer) {
      redirectServer.close();
    }
    try {
      fs8.unlinkSync(store.pidPath);
    } catch {
    }
    try {
      fs8.unlinkSync(store.portFilePath);
    } catch {
    }
    writeTlsMarker(store.dir, false);
    writeTldFile(store.dir, DEFAULT_TLD);
    writeLanMarker(store.dir, null);
    if (autoSyncHosts) cleanHostsFile();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), EXIT_TIMEOUT_MS).unref();
  };
  process.on("SIGINT", cleanup);
  process.on("SIGTERM", cleanup);
  console.log(colors_default.cyan("\nProxy is running. Press Ctrl+C to stop.\n"));
  console.log(colors_default.gray(`Routes file: ${store.getRoutesPath()}`));
}
function sudoStopOrHint(port) {
  if (!isWindows) {
    if (!sudoStop(port)) {
      console.error(colors_default.red("Failed to stop proxy with sudo."));
      console.error(colors_default.blue("Try manually:"));
      console.error(colors_default.cyan(`  portless proxy stop -p ${port}`));
    }
  } else {
    console.error(colors_default.red("Permission denied. The proxy was started with elevated privileges."));
    console.error(colors_default.blue("Stop it with:"));
    console.error(colors_default.cyan("  Run portless proxy stop as Administrator"));
  }
}
async function stopProxy(store, proxyPort, _tls) {
  const pidPath = store.pidPath;
  if (!fs8.existsSync(pidPath)) {
    if (await isProxyRunning(proxyPort)) {
      console.log(colors_default.yellow(`PID file is missing but port ${proxyPort} is still in use.`));
      const pid = findPidOnPort(proxyPort);
      if (pid !== null) {
        try {
          process.kill(pid, "SIGTERM");
          try {
            fs8.unlinkSync(store.portFilePath);
          } catch {
          }
          writeTlsMarker(store.dir, false);
          writeTldFile(store.dir, DEFAULT_TLD);
          writeLanMarker(store.dir, null);
          console.log(colors_default.green(`Killed process ${pid}. Proxy stopped.`));
        } catch (err) {
          if (isErrnoException(err) && err.code === "EPERM") {
            sudoStopOrHint(proxyPort);
          } else {
            const message = err instanceof Error ? err.message : String(err);
            console.error(colors_default.red(`Failed to stop proxy: ${message}`));
            console.error(colors_default.blue("Check if the process is still running:"));
            console.error(
              colors_default.cyan(
                isWindows ? `  netstat -ano | findstr :${proxyPort}` : `  lsof -ti tcp:${proxyPort}`
              )
            );
          }
        }
      } else if (!isWindows && process.getuid?.() !== 0) {
        sudoStopOrHint(proxyPort);
      } else {
        console.error(colors_default.red(`Could not identify the process on port ${proxyPort}.`));
        console.error(colors_default.blue("Try manually:"));
        console.error(
          colors_default.cyan(
            isWindows ? "  taskkill /F /PID <pid>" : `  sudo kill "$(lsof -ti tcp:${proxyPort})"`
          )
        );
      }
    } else {
      console.log(colors_default.yellow("Proxy is not running."));
    }
    return;
  }
  try {
    const pid = parseInt(fs8.readFileSync(pidPath, "utf-8"), 10);
    if (isNaN(pid)) {
      console.error(colors_default.red("Corrupted PID file. Removing it."));
      fs8.unlinkSync(pidPath);
      writeTlsMarker(store.dir, false);
      writeTldFile(store.dir, DEFAULT_TLD);
      writeLanMarker(store.dir, null);
      return;
    }
    try {
      process.kill(pid, 0);
    } catch (err) {
      if (isErrnoException(err) && err.code === "EPERM") {
        sudoStopOrHint(proxyPort);
        return;
      }
      console.log(colors_default.yellow("Proxy process is no longer running. Cleaning up stale files."));
      fs8.unlinkSync(pidPath);
      try {
        fs8.unlinkSync(store.portFilePath);
      } catch {
      }
      writeTlsMarker(store.dir, false);
      writeTldFile(store.dir, DEFAULT_TLD);
      writeLanMarker(store.dir, null);
      return;
    }
    if (!await isProxyRunning(proxyPort)) {
      console.log(
        colors_default.yellow(
          `PID file exists but port ${proxyPort} is not listening. The PID may have been recycled.`
        )
      );
      console.log(colors_default.yellow("Removing stale PID file."));
      fs8.unlinkSync(pidPath);
      writeTlsMarker(store.dir, false);
      writeTldFile(store.dir, DEFAULT_TLD);
      writeLanMarker(store.dir, null);
      return;
    }
    process.kill(pid, "SIGTERM");
    fs8.unlinkSync(pidPath);
    try {
      fs8.unlinkSync(store.portFilePath);
    } catch {
    }
    writeTlsMarker(store.dir, false);
    writeTldFile(store.dir, DEFAULT_TLD);
    writeLanMarker(store.dir, null);
    console.log(colors_default.green("Proxy stopped."));
  } catch (err) {
    if (isErrnoException(err) && err.code === "EPERM") {
      sudoStopOrHint(proxyPort);
    } else {
      const message = err instanceof Error ? err.message : String(err);
      console.error(colors_default.red(`Failed to stop proxy: ${message}`));
      console.error(colors_default.blue("Check if the process is still running:"));
      console.error(
        colors_default.cyan(
          isWindows ? `  netstat -ano | findstr :${proxyPort}` : `  lsof -ti tcp:${proxyPort}`
        )
      );
    }
  }
}
function listRoutes(store, proxyPort, tls2) {
  const routes = store.loadRoutes();
  if (routes.length === 0) {
    console.log(colors_default.yellow("No active routes."));
    console.log(colors_default.gray("Start an app with: portless <name> <command>"));
    return;
  }
  console.log(colors_default.blue.bold("\nActive routes:\n"));
  for (const route of routes) {
    const url = formatUrl(route.hostname, proxyPort, tls2);
    const label = route.pid === 0 ? "(alias)" : `(pid ${route.pid})`;
    console.log(
      `  ${colors_default.cyan(url)}  ${colors_default.gray("->")}  ${colors_default.white(`localhost:${route.port}`)}  ${colors_default.gray(label)}`
    );
    if (route.tailscaleUrl) {
      const tsLabel = route.tailscaleFunnel ? "funnel" : "tailscale";
      console.log(`    ${colors_default.gray(tsLabel + ":")} ${colors_default.green(route.tailscaleUrl)}`);
    }
  }
  console.log();
}
function resolveProxyDesiredState(lanMode) {
  const envTld = getDefaultTld();
  const explicit = {
    useHttps: process.env.PORTLESS_HTTPS !== void 0,
    customCert: false,
    lanMode: process.env.PORTLESS_LAN !== void 0,
    lanIp: process.env.PORTLESS_LAN_IP !== void 0,
    tld: process.env.PORTLESS_TLD !== void 0,
    useWildcard: process.env.PORTLESS_WILDCARD !== void 0
  };
  const desiredConfig = resolveProxyConfig({
    persistedLanMode: lanMode,
    explicit,
    defaultTld: envTld,
    useHttps: !isHttpsEnvDisabled(),
    customCertPath: null,
    customKeyPath: null,
    lanMode: isLanEnvEnabled(),
    lanIp: process.env.PORTLESS_LAN_IP || null,
    tld: envTld,
    useWildcard: isWildcardEnvEnabled()
  });
  return { explicit, desiredConfig, envTld };
}
async function ensureProxyRunning(proxyPort, tls2, desired) {
  const { explicit, desiredConfig } = desired;
  const proxyResponsive = await isProxyRunning(proxyPort, tls2);
  const proxyListeningFromStateDir = !!process.env.PORTLESS_STATE_DIR && await isPortListening(proxyPort);
  if (proxyResponsive || proxyListeningFromStateDir) {
    return { started: false };
  }
  const persisted = readPersistedProxyState();
  const startConfig = { ...desiredConfig };
  let startPort;
  if (persisted) {
    if (!explicit.useHttps && persisted.tls !== desiredConfig.useHttps) {
      startConfig.useHttps = persisted.tls;
    }
    if (!explicit.tld && persisted.tld !== desiredConfig.tld) {
      startConfig.tld = persisted.tld;
    }
    if (!explicit.lanMode && persisted.lanMode !== desiredConfig.lanMode) {
      startConfig.lanMode = persisted.lanMode;
    }
    const envPort = getDefaultPort(startConfig.useHttps);
    if (persisted.port !== envPort) {
      startPort = persisted.port;
    }
  }
  const effectivePort = startPort ?? getDefaultPort(startConfig.useHttps);
  const needsSudo = !isWindows && effectivePort < PRIVILEGED_PORT_THRESHOLD;
  const manualStartCommand = formatProxyStartCommand(effectivePort, startConfig);
  const fallbackStartCommand = formatProxyStartCommand(FALLBACK_PROXY_PORT, startConfig);
  const isInteractive = !!process.stdin.isTTY && !process.env.CI;
  if (needsSudo && !isInteractive) {
    console.error(colors_default.red("Proxy is not running and no TTY is available for sudo."));
    console.error(colors_default.blue("Option 1: start the proxy in a terminal (will prompt for sudo):"));
    console.error(colors_default.cyan(`  ${manualStartCommand}`));
    console.error(
      colors_default.blue(
        `Option 2: use an unprivileged port (no sudo needed, URLs will include :${FALLBACK_PROXY_PORT}):`
      )
    );
    console.error(colors_default.cyan(`  ${fallbackStartCommand}`));
    process.exit(1);
  }
  console.log(colors_default.gray("Starting proxy..."));
  const proxyStartConfig = buildProxyStartConfig({
    useHttps: startConfig.useHttps,
    customCertPath: startConfig.customCertPath,
    customKeyPath: startConfig.customKeyPath,
    lanMode: startConfig.lanMode,
    lanIp: startConfig.lanIpExplicit ? startConfig.lanIp : null,
    lanIpExplicit: startConfig.lanIpExplicit,
    tld: startConfig.tld,
    useWildcard: startConfig.useWildcard,
    includePort: startPort !== void 0,
    proxyPort: startPort
  });
  const startArgs = [getEntryScript(), "proxy", "start", ...proxyStartConfig.args];
  const result = spawnSync3(process.execPath, startArgs, {
    stdio: "inherit",
    timeout: SUDO_SPAWN_TIMEOUT_MS
  });
  let discovered = null;
  if (!result.signal) {
    for (let i = 0; i < WAIT_FOR_PROXY_MAX_ATTEMPTS; i++) {
      await new Promise((r) => setTimeout(r, WAIT_FOR_PROXY_INTERVAL_MS));
      const state = await discoverState();
      if (await isProxyRunning(state.port)) {
        discovered = state;
        break;
      }
    }
  }
  if (!discovered) {
    console.error(colors_default.red("Failed to start proxy."));
    const fallbackDir = resolveStateDir(effectivePort);
    const logPath = path8.join(fallbackDir, "proxy.log");
    console.error(colors_default.blue("Try starting it manually:"));
    console.error(colors_default.cyan(`  ${manualStartCommand}`));
    if (fs8.existsSync(logPath)) {
      console.error(colors_default.gray(`Logs: ${logPath}`));
    }
    process.exit(1);
    return { started: false };
  }
  return { started: true, state: discovered };
}
async function runApp(initialStore, proxyPort, stateDir, name, commandArgs, tls2, tld, force, autoInfo, desiredPort, lanMode = false, lanIp) {
  let store = initialStore;
  console.log(chalk.blue.bold(`
portless
`));
  const wantsFunnel = process.env.PORTLESS_FUNNEL === "1" || process.env.PORTLESS_FUNNEL === "true";
  const wantsTailscale = wantsFunnel || process.env.PORTLESS_TAILSCALE === "1" || process.env.PORTLESS_TAILSCALE === "true";
  let tsBaseUrl;
  if (wantsTailscale) {
    try {
      const tsReady = ensureTailscaleReady();
      tsBaseUrl = tsReady.baseUrl;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(colors_default.red(`Error: ${message}`));
      if (message.includes("not found")) {
        console.error(colors_default.blue("Install Tailscale: https://tailscale.com/download"));
      } else {
        console.error(colors_default.blue("Make sure Tailscale is connected:"));
        console.error(colors_default.cyan("  tailscale up"));
      }
      process.exit(1);
    }
  }
  let desired;
  try {
    desired = resolveProxyDesiredState(lanMode);
  } catch (err) {
    console.error(colors_default.red(`Error: ${err.message}`));
    process.exit(1);
  }
  parseHostname(name, tld);
  const ensureResult = await ensureProxyRunning(proxyPort, tls2, desired);
  if (ensureResult.started) {
    proxyPort = ensureResult.state.port;
    stateDir = ensureResult.state.dir;
    tld = ensureResult.state.tld;
    tls2 = ensureResult.state.tls;
    lanMode = ensureResult.state.lanMode;
    lanIp = ensureResult.state.lanIp;
    store = new RouteStore(stateDir, {
      onWarning: (msg) => console.warn(colors_default.yellow(msg))
    });
    if (tls2 && !isCATrusted(stateDir)) {
      await handleTrust();
    }
  } else {
    const runningConfig = readCurrentProxyConfig(stateDir);
    const mismatchMessages = getProxyConfigMismatchMessages(
      desired.desiredConfig,
      runningConfig,
      desired.explicit
    );
    if (mismatchMessages.length > 0) {
      printProxyConfigMismatch(proxyPort, desired.desiredConfig, mismatchMessages);
    }
    lanMode = runningConfig.lanMode;
    lanIp = runningConfig.lanIp;
    console.log(chalk.gray("-- Proxy is running"));
  }
  const hostname = parseHostname(name, tld);
  if (desired.envTld !== DEFAULT_TLD && desired.envTld !== tld) {
    console.warn(
      chalk.yellow(
        `Warning: PORTLESS_TLD=${desired.envTld} but the running proxy uses .${tld}. Using .${tld}.`
      )
    );
  }
  if (lanIp) {
    console.log(chalk.gray(`-- ${hostname} (LAN: ${lanIp})`));
  } else {
    console.log(chalk.gray(`-- ${hostname} (auto-resolves to 127.0.0.1)`));
  }
  if (autoInfo) {
    const baseName = autoInfo.prefix ? name.slice(autoInfo.prefix.length + 1) : name;
    console.log(chalk.gray(`-- Name "${baseName}" (from ${autoInfo.nameSource})`));
    if (autoInfo.prefix) {
      console.log(chalk.gray(`-- Prefix "${autoInfo.prefix}" (from ${autoInfo.prefixSource})`));
    }
  }
  const port = desiredPort ?? await findFreePort();
  if (desiredPort) {
    console.log(colors_default.green(`-- Using port ${port} (fixed)`));
  } else {
    console.log(colors_default.green(`-- Using port ${port}`));
  }
  let killedPid;
  try {
    killedPid = store.addRoute(hostname, port, process.pid, force);
  } catch (err) {
    if (err instanceof RouteConflictError) {
      console.error(colors_default.red(`Error: ${err.message}`));
      process.exit(1);
    }
    throw err;
  }
  if (killedPid !== void 0) {
    console.log(colors_default.yellow(`Killed existing process (PID ${killedPid})`));
  }
  const finalUrl = formatUrl(hostname, proxyPort, tls2);
  console.log(chalk.cyan.bold(`
  -> ${finalUrl}
`));
  if (lanIp) {
    console.log(chalk.green(`  LAN -> ${finalUrl}`));
    console.log(chalk.gray("  (accessible from other devices on the same WiFi network)\n"));
  }
  let tailscaleHttpsPort;
  let tailscaleUrl;
  if (wantsTailscale && tsBaseUrl) {
    const maxAttempts = 3;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const usedPorts = getUsedServePorts();
      tailscaleHttpsPort = findAvailableServePort(usedPorts, wantsFunnel ? "funnel" : "serve");
      try {
        if (wantsFunnel) {
          registerFunnel(port, tailscaleHttpsPort);
        } else {
          registerServe(port, tailscaleHttpsPort);
        }
        break;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        const isConflict = message.includes("already in use");
        if (isConflict && attempt < maxAttempts) continue;
        console.error(colors_default.red(`Error: ${message}`));
        process.exit(1);
      }
    }
    tailscaleUrl = formatTailscaleUrl(tsBaseUrl, tailscaleHttpsPort);
    const label = wantsFunnel ? "Funnel (public)" : "Tailscale";
    console.log(chalk.green(`  ${label} -> ${tailscaleUrl}`));
    if (wantsFunnel) {
      console.log(chalk.gray("  (accessible from the public internet via Tailscale Funnel)\n"));
    } else {
      console.log(chalk.gray("  (accessible from your tailnet)\n"));
    }
    try {
      store.updateRoute(hostname, {
        tailscaleUrl,
        tailscaleHttpsPort,
        tailscaleFunnel: wantsFunnel || void 0
      });
    } catch {
    }
  }
  const basename5 = path8.basename(commandArgs[0]);
  const isExpo = basename5 === "expo";
  const isExpoLan = isExpo && (lanMode || isLanEnvEnabled());
  const hostBind = isExpoLan ? void 0 : "127.0.0.1";
  if (lanMode && !process.env.PORTLESS_LAN) {
    process.env.PORTLESS_LAN = "1";
  }
  injectFrameworkFlags(commandArgs, port);
  const caEnv = {};
  if (tls2 && !process.env.NODE_EXTRA_CA_CERTS) {
    const caPath = path8.join(stateDir, "ca.pem");
    if (fs8.existsSync(caPath)) {
      caEnv.NODE_EXTRA_CA_CERTS = caPath;
    }
  }
  const caFragment = caEnv.NODE_EXTRA_CA_CERTS ? ` NODE_EXTRA_CA_CERTS="${caEnv.NODE_EXTRA_CA_CERTS}"` : "";
  console.log(
    chalk.gray(
      `Running: PORT=${port}${hostBind ? ` HOST=${hostBind}` : ""} PORTLESS_URL=${finalUrl}${caFragment} ${commandArgs.join(" ")}
`
    )
  );
  spawnCommand(commandArgs, {
    env: {
      ...process.env,
      PORT: port.toString(),
      ...hostBind ? { HOST: hostBind } : {},
      PORTLESS_URL: finalUrl,
      __VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS: `.${tld}`,
      // Note: EXPO_PACKAGER_PROXY_URL is not used — expo-dev-client removed
      // baked-in pinging, making this env var ineffective. Expo handles its
      // own LAN discovery natively.
      ...lanMode ? { PORTLESS_LAN: "1" } : {},
      ...tailscaleUrl ? { PORTLESS_TAILSCALE_URL: tailscaleUrl } : {},
      ...caEnv
    },
    onCleanup: () => {
      try {
        unregisterTailscale({
          tailscaleHttpsPort,
          tailscaleFunnel: wantsFunnel || void 0
        });
      } catch {
      }
      try {
        store.removeRoute(hostname);
      } catch {
      }
    }
  });
}
function parseAppPort(value) {
  if (!value || value.startsWith("--")) {
    console.error(colors_default.red("Error: --app-port requires a port number."));
    process.exit(1);
  }
  const port = parseInt(value, 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    console.error(colors_default.red(`Error: Invalid app port "${value}". Must be 1-65535.`));
    process.exit(1);
  }
  return port;
}
function appPortFromEnv() {
  const envVal = process.env.PORTLESS_APP_PORT;
  if (!envVal) return void 0;
  const port = parseInt(envVal, 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    console.error(colors_default.red(`Error: Invalid PORTLESS_APP_PORT="${envVal}". Must be 1-65535.`));
    process.exit(1);
  }
  return port;
}
function applyTailscaleFlag(flag) {
  if (flag === "--tailscale") {
    process.env.PORTLESS_TAILSCALE = "1";
    return true;
  }
  if (flag === "--funnel") {
    process.env.PORTLESS_FUNNEL = "1";
    process.env.PORTLESS_TAILSCALE = "1";
    return true;
  }
  return false;
}
function parseRunArgs(args) {
  let force = false;
  let appPort;
  let name;
  let i = 0;
  while (i < args.length && args[i].startsWith("-")) {
    if (args[i] === "--") {
      i++;
      break;
    } else if (args[i] === "--help" || args[i] === "-h") {
      console.log(`
${colors_default.bold("portless run")} - Infer project name and run through the proxy.

${colors_default.bold("Usage:")}
  ${colors_default.cyan("portless run [options] [command...]")}

  When no command is given, runs the configured script (default: "dev")
  from package.json.

${colors_default.bold("Options:")}
  --name <name>          Override the inferred base name (worktree prefix still applies)
  --force                Kill the existing process and take over its route
  --app-port <number>    Use a fixed port for the app (skip auto-assignment)
  --help, -h             Show this help

${colors_default.bold("Name inference (in order):")}
  1. portless.json "name" field
  2. package.json "name" field (walks up directories)
  3. Git repo root directory name
  4. Current directory basename

  Use --name to override the inferred name while keeping worktree prefixes.
  In git worktrees, the branch name is prepended as a subdomain prefix
  (e.g. feature-auth.myapp.localhost).

${colors_default.bold("Examples:")}
  portless run                        # Run dev script through proxy
  portless run next dev               # -> https://<project>.localhost
  portless run --name myapp next dev  # -> https://myapp.localhost
  portless run vite dev               # -> https://<project>.localhost
  portless run --app-port 3000 pnpm start
`);
      process.exit(0);
    } else if (args[i] === "--force") {
      force = true;
    } else if (args[i] === "--app-port") {
      i++;
      appPort = parseAppPort(args[i]);
    } else if (args[i] === "--name") {
      i++;
      if (!args[i] || args[i].startsWith("-")) {
        console.error(colors_default.red("Error: --name requires a name value."));
        console.error(colors_default.cyan("  portless run --name <name> <command...>"));
        process.exit(1);
      }
      name = args[i];
    } else if (applyTailscaleFlag(args[i])) {
    } else {
      console.error(colors_default.red(`Error: Unknown flag "${args[i]}".`));
      console.error(
        colors_default.blue("Known flags: --name, --force, --app-port, --tailscale, --funnel, --help")
      );
      process.exit(1);
    }
    i++;
  }
  if (!appPort) appPort = appPortFromEnv();
  return { force, appPort, name, commandArgs: args.slice(i) };
}
function parseAppArgs(args) {
  let force = false;
  let appPort;
  let i = 0;
  while (i < args.length && args[i].startsWith("-")) {
    if (args[i] === "--") {
      i++;
      break;
    } else if (args[i] === "--force") {
      force = true;
    } else if (args[i] === "--app-port") {
      i++;
      appPort = parseAppPort(args[i]);
    } else if (applyTailscaleFlag(args[i])) {
    } else {
      console.error(colors_default.red(`Error: Unknown flag "${args[i]}".`));
      console.error(colors_default.blue("Known flags: --force, --app-port, --tailscale, --funnel"));
      process.exit(1);
    }
    i++;
  }
  const name = args[i];
  i++;
  while (i < args.length && args[i].startsWith("--")) {
    if (args[i] === "--") {
      i++;
      break;
    } else if (args[i] === "--force") {
      force = true;
    } else if (args[i] === "--app-port") {
      i++;
      appPort = parseAppPort(args[i]);
    } else if (applyTailscaleFlag(args[i])) {
    } else {
      console.error(colors_default.red(`Error: Unknown flag "${args[i]}".`));
      console.error(colors_default.blue("Known flags: --force, --app-port, --tailscale, --funnel"));
      process.exit(1);
    }
    i++;
  }
  if (!appPort) appPort = appPortFromEnv();
  return { force, appPort, name, commandArgs: args.slice(i) };
}
function printHelp() {
  console.log(`
${colors_default.bold("portless")} - Replace port numbers with stable, named .localhost URLs. For humans and agents.

Eliminates port conflicts, memorizing port numbers, and cookie/storage
clashes by giving each dev server a stable .localhost URL.

${colors_default.bold("Install:")}
  ${colors_default.cyan("npm install -g portless")}          Global (recommended)
  ${colors_default.cyan("npm install -D portless")}          Project dev dependency

${colors_default.bold("Usage:")}
  ${colors_default.cyan("portless")}                         Run dev script through proxy
  ${colors_default.cyan("portless")}                         From monorepo root: run all workspace packages
  ${colors_default.cyan("portless run")}                     Same as above
  ${colors_default.cyan("portless run <cmd>")}               Run a command through the proxy
  ${colors_default.cyan("portless <name> <cmd>")}            Run with an explicit app name
  ${colors_default.cyan("portless proxy start")}             Start the proxy (HTTPS on port 443, daemon)
  ${colors_default.cyan("portless proxy stop")}              Stop the proxy
  ${colors_default.cyan("portless get <name>")}              Print URL for a service (for cross-service refs)
  ${colors_default.cyan("portless alias <name> <port>")}     Register a static route (e.g. for Docker)
  ${colors_default.cyan("portless alias --remove <name>")}   Remove a static route
  ${colors_default.cyan("portless list")}                    Show active routes
  ${colors_default.cyan("portless trust")}                   Add local CA to system trust store
  ${colors_default.cyan("portless clean")}                   Remove portless state, trust entry, and hosts block
  ${colors_default.cyan("portless prune")}                   Kill orphaned dev servers from crashed sessions
  ${colors_default.cyan("portless hosts sync")}              Add routes to ${HOSTS_DISPLAY} (fixes Safari)
  ${colors_default.cyan("portless hosts clean")}             Remove portless entries from ${HOSTS_DISPLAY}

${colors_default.bold("Examples:")}
  portless                            # Run dev script through proxy
  portless                            # From monorepo root: start all apps
  portless --script start             # Run "start" script instead of "dev"
  portless myapp next dev             # -> https://myapp.localhost
  portless run next dev               # -> https://<project>.localhost
  portless run next dev               # in worktree -> https://<worktree>.<project>.localhost
  portless get backend                # -> https://backend.localhost
  portless myapp --tailscale next dev # -> also https://<node>.ts.net (tailnet)
  portless myapp --funnel next dev    # -> also https://<node>.ts.net (public)

${colors_default.bold("Configuration (portless.json):")}
  Optional. Portless works out of the box by running the "dev" script
  from package.json. Use portless.json to override defaults.

  Override name:   { "name": "myapp" }
  Override script: { "name": "myapp", "script": "start" }
  Monorepo:        { "apps": { "apps/web": { "name": "myapp" } } }

${colors_default.bold("In package.json:")}
  {
    "scripts": {
      "dev": "next dev"
    }
  }
  Then run: portless
  Or:       portless run
  Or:       portless run next dev

${colors_default.bold("How it works:")}
  1. Start the proxy once (HTTPS on port 443 by default, auto-elevates with sudo)
  2. Run your apps - they auto-start the proxy and register automatically
     (apps get a random port in the 4000-4999 range via PORT)
  3. Access via https://<name>.localhost
  4. .localhost domains auto-resolve to 127.0.0.1
  5. Frameworks that ignore PORT (Vite, VitePlus, Astro, React Router, Angular,
     Expo, React Native) get --port and, when needed, --host flags
     injected automatically

${colors_default.bold("HTTP/2 + HTTPS (default):")}
  HTTPS with HTTP/2 multiplexing is enabled by default (faster page loads).
  On first use, portless generates a local CA and adds it to your
  system trust store. No browser warnings. Disable with --no-tls.

${colors_default.bold("LAN mode:")}
  Use --lan to make services accessible from other devices (phones,
  tablets) on the same WiFi network via mDNS (.local domains).
  Useful for testing React Native / Expo apps on real devices.
  Expo keeps Metro's default LAN host behavior in this mode.
  Auto-detected LAN IPs follow network changes automatically.
  Stopped LAN proxies keep LAN mode for the next start via proxy.lan.
  All proxy settings are persisted and reused on auto-start unless
  overridden by explicit flags or env vars.
  Use PORTLESS_LAN=0 for one start to switch back to .localhost mode.
  If a proxy is already running with different explicit LAN/TLS/TLD settings,
  stop it first.
  ${colors_default.cyan("portless proxy start --lan")}
  ${colors_default.cyan("portless proxy start --lan --https")}
  ${colors_default.cyan("portless proxy start --lan --ip 192.168.1.42")}

${colors_default.bold("Tailscale sharing:")}
  Use --tailscale to share your dev server with teammates on your tailnet.
  Each app is root-mounted on its own Tailscale HTTPS port (443, then 8443,
  8444, etc.) so no basePath configuration is needed.
  Use --funnel to expose your dev server to the public internet via
  Tailscale Funnel. Requires Tailscale CLI to be installed and connected.
  ${colors_default.cyan("portless myapp --tailscale next dev")}
  ${colors_default.cyan("portless myapp --funnel next dev")}

${colors_default.bold("Options:")}
  run [--name <name>] <cmd>      Infer project name (or override with --name)
                                Adds worktree prefix in git worktrees
  --script <name>               Run a specific package.json script (default: dev)
  -p, --port <number>           Port for the proxy (default: 443, or 80 with --no-tls)
                                Standard ports auto-elevate with sudo on macOS/Linux
  --no-tls                      Disable HTTPS (use plain HTTP on port 80)
  --https                       Enable HTTPS (default, accepted for compatibility)
  --lan                         Enable LAN mode (mDNS .local, for real device testing)
  --ip <address>                Pin a specific LAN IP (disables auto-follow; use with --lan)
  --cert <path>                 Use a custom TLS certificate
  --key <path>                  Use a custom TLS private key
  --foreground                  Run proxy in foreground (for debugging)
  --tld <tld>                   Use a custom TLD instead of .localhost (e.g. test, dev)
  --wildcard                    Allow unregistered subdomains to fall back to parent route
  --app-port <number>           Use a fixed port for the app (skip auto-assignment)
  --tailscale                   Share the app on your Tailscale network (tailnet)
  --funnel                      Share the app publicly via Tailscale Funnel
  --force                       Kill the existing process and take over its route
  --name <name>                 Use <name> as the app name (bypasses subcommand dispatch)
  --                            Stop flag parsing; everything after is passed to the child

${colors_default.bold("Environment variables:")}
  PORTLESS_PORT=<number>        Override the default proxy port (e.g. in .bashrc)
  PORTLESS_APP_PORT=<number>    Use a fixed port for the app (same as --app-port)
  PORTLESS_HTTPS=0              Disable HTTPS (same as --no-tls)
  PORTLESS_LAN=1                Enable LAN mode when set to 1 (set in .bashrc / .zshrc)
  PORTLESS_TLD=<tld>            Use a custom TLD (e.g. test, dev; default: localhost)
  PORTLESS_WILDCARD=1           Allow unregistered subdomains to fall back to parent route
  PORTLESS_SYNC_HOSTS=0         Disable auto-sync of ${HOSTS_DISPLAY} (on by default)
  PORTLESS_TAILSCALE=1          Share apps on your Tailscale network (same as --tailscale)
  PORTLESS_FUNNEL=1             Share apps publicly via Tailscale Funnel (same as --funnel)
  PORTLESS_STATE_DIR=<path>     Override the state directory
  PORTLESS=0                    Run command directly without proxy

${colors_default.bold("Child process environment:")}
  PORT                          Ephemeral port the child should listen on
  HOST                          Usually 127.0.0.1 (omitted for Expo in LAN mode)
  PORTLESS_URL                  Public URL of the app (e.g. https://myapp.localhost)
  PORTLESS_LAN                  Set to 1 when proxy is in LAN mode
  PORTLESS_TAILSCALE_URL        Tailscale URL of the app (when --tailscale is active)
  NODE_EXTRA_CA_CERTS           Path to the portless CA (set when HTTPS is active)

${colors_default.bold("Safari / DNS:")}
  .localhost subdomains auto-resolve in Chrome, Firefox, and Edge.
  Safari relies on the system DNS resolver, which may not handle them.
  Auto-syncs ${HOSTS_DISPLAY} for route hostnames by default (including .localhost,
  custom TLDs, and LAN .local). Set PORTLESS_SYNC_HOSTS=0 to disable. To manually sync:
    ${colors_default.cyan("portless hosts sync")}
  Clean up later with:
    ${colors_default.cyan("portless hosts clean")}

${colors_default.bold("Skip portless:")}
  PORTLESS=0 pnpm dev           # Runs command directly without proxy

${colors_default.bold("Reserved names:")}
  run, get, alias, hosts, list, trust, clean, prune, proxy are subcommands and
  cannot be used as app names directly. Use "portless run" to infer the name,
  or "portless --name <name>" to force any name including reserved ones.
`);
  process.exit(0);
}
function printVersion() {
  console.log("0.11.1");
  process.exit(0);
}
async function handleTrust() {
  const { dir } = await discoverState();
  if (!fs8.existsSync(dir)) {
    fs8.mkdirSync(dir, { recursive: true });
  }
  const { caGenerated } = ensureCerts(dir);
  if (caGenerated) {
    console.log(colors_default.gray("Generated local CA certificate."));
  }
  const result = trustCA(dir);
  if (result.trusted) {
    console.log(colors_default.green("Local CA added to system trust store."));
    console.log(colors_default.gray("Browsers will now trust portless HTTPS certificates."));
    return;
  }
  const isPermissionError = result.error?.includes("Permission denied") || result.error?.includes("EACCES");
  if (isPermissionError && !isWindows && process.getuid?.() !== 0) {
    console.log(colors_default.yellow("Trusting the CA requires elevated privileges. Requesting sudo..."));
    const sudoResult = spawnSync3(
      "sudo",
      [
        "env",
        ...collectPortlessEnvArgs(),
        `PORTLESS_STATE_DIR=${dir}`,
        process.execPath,
        getEntryScript(),
        "trust"
      ],
      {
        stdio: "inherit",
        timeout: SUDO_SPAWN_TIMEOUT_MS
      }
    );
    if (sudoResult.status === 0) return;
    console.error(colors_default.red("sudo elevation also failed."));
  }
  console.error(colors_default.red(`Failed to trust CA: ${result.error}`));
  process.exit(1);
}
async function handleClean(args) {
  if (args[1] === "--help" || args[1] === "-h") {
    console.log(`
${colors_default.bold("portless clean")} - Remove portless artifacts from this machine.

Stops the proxy if it is running, removes the local CA from the OS trust store
when it was installed by portless, deletes known files under state directories
(~/.portless, the system state directory, and PORTLESS_STATE_DIR when set),
and removes the portless block from ${HOSTS_DISPLAY}.

Only allowlisted filenames under each state directory are deleted. Custom
certificate paths from --cert and --key are never removed.

macOS/Linux may prompt for sudo when the proxy, trust store, or ${HOSTS_DISPLAY}
require elevated privileges. On Windows, run as Administrator if needed.

${colors_default.bold("Usage:")}
  ${colors_default.cyan("portless clean")}

${colors_default.bold("Options:")}
  --help, -h             Show this help
`);
    process.exit(0);
  }
  if (args.length > 1) {
    console.error(colors_default.red(`Error: Unknown argument "${args[1]}".`));
    console.error(colors_default.cyan("  portless clean --help"));
    process.exit(1);
  }
  console.log(colors_default.cyan("Stopping proxy if it is running..."));
  const { dir, port, tls: tls2 } = await discoverState();
  const store = new RouteStore(dir, {
    onWarning: (msg) => console.warn(colors_default.yellow(msg))
  });
  await stopProxy(store, port, tls2);
  const routesForClean = store.loadRoutesRaw();
  for (const route of routesForClean) {
    if (route.tailscaleHttpsPort) {
      try {
        unregisterTailscale(route);
        console.log(colors_default.green(`Removed tailscale serve on port ${route.tailscaleHttpsPort}.`));
      } catch {
      }
    }
  }
  const stateDirs = collectStateDirsForCleanup();
  for (const stateDir of stateDirs) {
    const caPath = path8.join(stateDir, "ca.pem");
    if (!fs8.existsSync(caPath)) continue;
    const wasTrusted = isCATrusted(stateDir);
    if (!wasTrusted) continue;
    const untrustResult = untrustCA(stateDir);
    if (untrustResult.removed) {
      console.log(colors_default.green("Removed local CA from the system trust store."));
    } else if (untrustResult.error) {
      console.warn(
        colors_default.yellow(
          `Could not remove CA from trust store: ${untrustResult.error}
Try: sudo portless clean (Linux), or delete the certificate manually.`
        )
      );
    }
  }
  for (const stateDir of stateDirs) {
    removePortlessStateFiles(stateDir);
  }
  console.log(colors_default.green("Removed portless state files from known state directories."));
  if (cleanHostsFile()) {
    console.log(colors_default.green(`Removed portless entries from ${HOSTS_DISPLAY}.`));
  } else if (!isWindows && process.getuid?.() !== 0) {
    console.log(
      colors_default.yellow(`Updating ${HOSTS_DISPLAY} requires elevated privileges. Requesting sudo...`)
    );
    const result = spawnSync3(
      "sudo",
      ["env", ...collectPortlessEnvArgs(), process.execPath, getEntryScript(), "clean"],
      {
        stdio: "inherit",
        timeout: SUDO_SPAWN_TIMEOUT_MS
      }
    );
    if (result.status !== 0) {
      console.error(colors_default.red(`Failed to update ${HOSTS_DISPLAY}. Run: sudo portless clean`));
      process.exit(1);
    }
  } else {
    console.warn(
      colors_default.yellow(
        `Could not remove portless entries from ${HOSTS_DISPLAY}${isWindows ? " (run as Administrator)." : "."}`
      )
    );
  }
  console.log(colors_default.green("Clean finished."));
}
async function handlePrune(args) {
  if (args[1] === "--help" || args[1] === "-h") {
    console.log(`
${colors_default.bold("portless prune")} - Kill orphaned dev servers left behind by crashed portless sessions.

When portless is killed with SIGKILL (kill -9) or crashes, child dev servers
may survive and continue holding their ports. This command finds those orphans
by checking routes whose owning CLI process is dead but whose port is still in
use, then terminates them and cleans up the stale route entries.

${colors_default.bold("Usage:")}
  ${colors_default.cyan("portless prune")}
  ${colors_default.cyan("portless prune --force")}     Send SIGKILL instead of SIGTERM

${colors_default.bold("Options:")}
  --force                Send SIGKILL instead of SIGTERM
  --help, -h             Show this help
`);
    process.exit(0);
  }
  const forceKill = args.includes("--force");
  const { dir } = await discoverState();
  const store = new RouteStore(dir, {
    onWarning: (msg) => console.warn(colors_default.yellow(msg))
  });
  const stale = store.pruneStaleRoutes();
  if (stale.length === 0) {
    console.log("No orphaned routes found.");
    return;
  }
  for (const route of stale) {
    if (route.tailscaleHttpsPort) {
      try {
        unregisterTailscale(route);
        console.log(
          `  ${route.hostname} - removed tailscale serve on port ${route.tailscaleHttpsPort}`
        );
      } catch {
      }
    }
  }
  let killed = 0;
  for (const route of stale) {
    const pids = findPidsOnPort(route.port);
    if (pids.length === 0) {
      console.log(`  ${route.hostname} :${route.port} - route removed (port already free)`);
      continue;
    }
    const signal = forceKill ? "SIGKILL" : "SIGTERM";
    for (const pid of pids) {
      try {
        process.kill(pid, signal);
        killed++;
        console.log(`  ${route.hostname} :${route.port} - killed PID ${pid} (${signal})`);
      } catch {
        console.log(`  ${route.hostname} :${route.port} - PID ${pid} already exited`);
      }
    }
  }
  const routeWord = stale.length === 1 ? "route" : "routes";
  const procWord = killed === 1 ? "process" : "processes";
  console.log(
    colors_default.green(
      `
Pruned ${stale.length} stale ${routeWord}, killed ${killed} orphaned ${procWord}.`
    )
  );
}
async function handleList() {
  const { dir, port, tls: tls2 } = await discoverState();
  const store = new RouteStore(dir, {
    onWarning: (msg) => console.warn(colors_default.yellow(msg))
  });
  listRoutes(store, port, tls2);
}
async function handleGet(args) {
  if (args[1] === "--help" || args[1] === "-h") {
    console.log(`
${colors_default.bold("portless get")} - Print the URL for a service.

${colors_default.bold("Usage:")}
  ${colors_default.cyan("portless get <name>")}

Constructs the URL using the same hostname and worktree logic as
"portless run", then prints it to stdout. Useful for wiring services
together:

  BACKEND_URL=$(portless get backend)

${colors_default.bold("Options:")}
  --no-worktree          Skip worktree prefix detection
  --help, -h             Show this help

${colors_default.bold("Examples:")}
  portless get backend                  # -> https://backend.localhost
  portless get backend                  # in worktree -> https://auth.backend.localhost
  portless get backend --no-worktree    # -> https://backend.localhost (skip worktree)
`);
    process.exit(0);
  }
  let skipWorktree = false;
  const positional = [];
  for (let i = 1; i < args.length; i++) {
    if (args[i] === "--no-worktree") {
      skipWorktree = true;
    } else if (args[i].startsWith("-")) {
      console.error(colors_default.red(`Error: Unknown flag "${args[i]}".`));
      console.error(colors_default.blue("Known flags: --no-worktree, --help"));
      process.exit(1);
    } else {
      positional.push(args[i]);
    }
  }
  if (positional.length === 0) {
    console.error(colors_default.red("Error: Missing service name."));
    console.error(colors_default.blue("Usage:"));
    console.error(colors_default.cyan("  portless get <name>"));
    console.error(colors_default.blue("Example:"));
    console.error(colors_default.cyan("  portless get backend"));
    process.exit(1);
  }
  const name = positional[0];
  const worktree = skipWorktree ? null : detectWorktreePrefix();
  const effectiveName = worktree ? `${worktree.prefix}.${name}` : name;
  const { port, tls: tls2, tld } = await discoverState();
  const hostname = parseHostname(effectiveName, tld);
  const url = formatUrl(hostname, port, tls2);
  process.stdout.write(url + "\n");
}
async function handleAlias(args) {
  if (args[1] === "--help" || args[1] === "-h") {
    console.log(`
${colors_default.bold("portless alias")} - Register a static route for services not managed by portless.

${colors_default.bold("Usage:")}
  ${colors_default.cyan("portless alias <name> <port>")}        Register a route
  ${colors_default.cyan("portless alias --remove <name>")}      Remove a route
  ${colors_default.cyan("portless alias <name> <port> --force")} Override existing route

${colors_default.bold("Examples:")}
  portless alias my-postgres 5432     # -> https://my-postgres.localhost
  portless alias redis 6379           # -> https://redis.localhost
  portless alias --remove my-postgres # Remove the alias
`);
    process.exit(0);
  }
  const { dir, tld } = await discoverState();
  const store = new RouteStore(dir, {
    onWarning: (msg) => console.warn(colors_default.yellow(msg))
  });
  if (args[1] === "--remove") {
    const aliasName2 = args[2];
    if (!aliasName2) {
      console.error(colors_default.red("Error: No alias name provided."));
      console.error(colors_default.cyan("  portless alias --remove <name>"));
      process.exit(1);
    }
    const hostname2 = parseHostname(aliasName2, tld);
    const routes = store.loadRoutes();
    const existing = routes.find((r) => r.hostname === hostname2 && r.pid === 0);
    if (!existing) {
      console.error(colors_default.red(`Error: No alias found for "${hostname2}".`));
      process.exit(1);
    }
    store.removeRoute(hostname2);
    console.log(colors_default.green(`Removed alias: ${hostname2}`));
    return;
  }
  const aliasName = args[1];
  const aliasPort = args[2];
  if (!aliasName || !aliasPort) {
    console.error(colors_default.red("Error: Missing arguments."));
    console.error(colors_default.blue("Usage:"));
    console.error(colors_default.cyan("  portless alias <name> <port>"));
    console.error(colors_default.cyan("  portless alias --remove <name>"));
    console.error(colors_default.blue("Example:"));
    console.error(colors_default.cyan("  portless alias my-postgres 5432"));
    process.exit(1);
  }
  const hostname = parseHostname(aliasName, tld);
  const port = parseInt(aliasPort, 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    console.error(colors_default.red(`Error: Invalid port "${aliasPort}". Must be 1-65535.`));
    process.exit(1);
  }
  const force = args.includes("--force");
  store.addRoute(hostname, port, 0, force);
  console.log(colors_default.green(`Alias registered: ${hostname} -> 127.0.0.1:${port}`));
}
async function handleHosts(args) {
  if (args[1] === "--help" || args[1] === "-h") {
    console.log(`
${colors_default.bold("portless hosts")} - Manage ${HOSTS_DISPLAY} entries for .localhost subdomains.

Safari relies on the system DNS resolver, which may not handle .localhost
subdomains. This command adds entries to ${HOSTS_DISPLAY} as a workaround.

${colors_default.bold("Usage:")}
  ${colors_default.cyan("portless hosts sync")}    Add current routes to ${HOSTS_DISPLAY}
  ${colors_default.cyan("portless hosts clean")}   Remove portless entries from ${HOSTS_DISPLAY}

${colors_default.bold("Auto-sync:")}
  The proxy updates ${HOSTS_DISPLAY} for route hostnames by default. Disable with
  PORTLESS_SYNC_HOSTS=0.
`);
    process.exit(0);
  }
  if (args[1] === "clean") {
    if (cleanHostsFile()) {
      console.log(colors_default.green(`Removed portless entries from ${HOSTS_DISPLAY}.`));
      return;
    }
    if (!isWindows && process.getuid?.() !== 0) {
      console.log(
        colors_default.yellow(
          `Writing to ${HOSTS_DISPLAY} requires elevated privileges. Requesting sudo...`
        )
      );
      const result = spawnSync3(
        "sudo",
        ["env", ...collectPortlessEnvArgs(), process.execPath, getEntryScript(), "hosts", "clean"],
        {
          stdio: "inherit",
          timeout: SUDO_SPAWN_TIMEOUT_MS
        }
      );
      if (result.status === 0) return;
    }
    console.error(
      colors_default.red(`Failed to update ${HOSTS_DISPLAY}${isWindows ? " (run as Administrator)." : "."}`)
    );
    process.exit(1);
    return;
  }
  if (!args[1]) {
    console.log(`
${colors_default.bold("Usage: portless hosts <command>")}

  ${colors_default.cyan("portless hosts sync")}    Add current routes to ${HOSTS_DISPLAY}
  ${colors_default.cyan("portless hosts clean")}   Remove portless entries from ${HOSTS_DISPLAY}
`);
    process.exit(0);
  }
  if (args[1] !== "sync") {
    console.error(colors_default.red(`Error: Unknown hosts subcommand "${args[1]}".`));
    console.error(colors_default.blue("Usage:"));
    console.error(colors_default.cyan(`  portless hosts sync    # Add routes to ${HOSTS_DISPLAY}`));
    console.error(colors_default.cyan("  portless hosts clean   # Remove portless entries"));
    process.exit(1);
  }
  const { dir } = await discoverState();
  const store = new RouteStore(dir, {
    onWarning: (msg) => console.warn(colors_default.yellow(msg))
  });
  const routes = store.loadRoutes();
  if (routes.length === 0) {
    console.log(colors_default.yellow("No active routes to sync."));
    return;
  }
  const hostnames = routes.map((r) => r.hostname);
  if (syncHostsFile(hostnames)) {
    console.log(colors_default.green(`Synced ${hostnames.length} hostname(s) to ${HOSTS_DISPLAY}:`));
    for (const h of hostnames) {
      console.log(colors_default.cyan(`  127.0.0.1 ${h}`));
    }
    return;
  }
  if (!isWindows && process.getuid?.() !== 0) {
    console.log(
      colors_default.yellow(`Writing to ${HOSTS_DISPLAY} requires elevated privileges. Requesting sudo...`)
    );
    const result = spawnSync3(
      "sudo",
      ["env", ...collectPortlessEnvArgs(), process.execPath, getEntryScript(), "hosts", "sync"],
      {
        stdio: "inherit",
        timeout: SUDO_SPAWN_TIMEOUT_MS
      }
    );
    if (result.status === 0) return;
  }
  console.error(
    colors_default.red(`Failed to update ${HOSTS_DISPLAY}${isWindows ? " (run as Administrator)." : "."}`)
  );
  process.exit(1);
}
async function handleProxy(args) {
  if (args[1] === "stop") {
    let explicitPort;
    const portIdx = args.indexOf("--port") !== -1 ? args.indexOf("--port") : args.indexOf("-p");
    if (portIdx !== -1) {
      const portValue = args[portIdx + 1];
      if (portValue && !portValue.startsWith("-")) {
        const parsed = parseInt(portValue, 10);
        if (!isNaN(parsed) && parsed >= 1 && parsed <= 65535) {
          explicitPort = parsed;
        }
      }
    }
    if (explicitPort !== void 0) {
      const dir = resolveStateDir(explicitPort);
      const store2 = new RouteStore(dir, {
        onWarning: (msg) => console.warn(colors_default.yellow(msg))
      });
      await stopProxy(store2, explicitPort, false);
    } else {
      const { dir, port, tls: tls2 } = await discoverState();
      const store2 = new RouteStore(dir, {
        onWarning: (msg) => console.warn(colors_default.yellow(msg))
      });
      await stopProxy(store2, port, tls2);
    }
    return;
  }
  const isProxyHelp = args[1] === "--help" || args[1] === "-h";
  if (isProxyHelp || args[1] !== "start") {
    console.log(`
${colors_default.bold("portless proxy")} - Manage the portless proxy server.

${colors_default.bold("Usage:")}
  ${colors_default.cyan("portless proxy start")}                Start the HTTPS proxy on port 443 (daemon)
  ${colors_default.cyan("portless proxy start --no-tls")}       Start without HTTPS (port 80)
  ${colors_default.cyan("portless proxy start --lan")}          Enable LAN mode (mDNS, .local TLD)
  ${colors_default.cyan("portless proxy start --foreground")}   Start in foreground (for debugging)
  ${colors_default.cyan("portless proxy start -p 1355")}        Start on a custom port (no sudo)
  ${colors_default.cyan("portless proxy start --tld test")}     Use .test instead of .localhost
  ${colors_default.cyan("portless proxy start --wildcard")}     Allow unregistered subdomains to fall back to parent
  ${colors_default.cyan("portless proxy stop")}                 Stop the proxy

${colors_default.bold("LAN mode (--lan):")}
  Makes services accessible from other devices on the same WiFi network
  via mDNS (.local domains). Useful for testing on real mobile devices.
  Auto-detects your LAN IP and follows changes automatically, or use
  --ip to pin one.
  Stopped LAN proxies keep LAN mode for the next start via proxy.lan.
  Use PORTLESS_LAN=0 for one start to switch back to .localhost mode.
`);
    process.exit(isProxyHelp || !args[1] ? 0 : 1);
  }
  const isForeground = args.includes("--foreground");
  const skipTrust = args.includes("--skip-trust");
  const hasHttpsFlag = args.includes("--https");
  const hasNoTls = args.includes("--no-tls") || isHttpsEnvDisabled();
  const wantHttps = !hasNoTls;
  let customCertPath = null;
  let customKeyPath = null;
  const certIdx = args.indexOf("--cert");
  if (certIdx !== -1) {
    customCertPath = args[certIdx + 1] || null;
    if (!customCertPath || customCertPath.startsWith("-")) {
      console.error(colors_default.red("Error: --cert requires a file path."));
      process.exit(1);
    }
  }
  const keyIdx = args.indexOf("--key");
  if (keyIdx !== -1) {
    customKeyPath = args[keyIdx + 1] || null;
    if (!customKeyPath || customKeyPath.startsWith("-")) {
      console.error(colors_default.red("Error: --key requires a file path."));
      process.exit(1);
    }
  }
  if (customCertPath && !customKeyPath || !customCertPath && customKeyPath) {
    console.error(colors_default.red("Error: --cert and --key must be used together."));
    process.exit(1);
  }
  let useHttps = wantHttps || !!(customCertPath && customKeyPath);
  let hasExplicitPort = false;
  let proxyPort = getDefaultPort(useHttps);
  let portFlagIndex = args.indexOf("--port");
  if (portFlagIndex === -1) portFlagIndex = args.indexOf("-p");
  if (portFlagIndex !== -1) {
    const portValue = args[portFlagIndex + 1];
    if (!portValue || portValue.startsWith("-")) {
      console.error(colors_default.red("Error: --port / -p requires a port number."));
      console.error(colors_default.blue("Usage:"));
      console.error(colors_default.cyan("  portless proxy start -p 8080"));
      process.exit(1);
    }
    proxyPort = parseInt(portValue, 10);
    if (isNaN(proxyPort) || proxyPort < 1 || proxyPort > 65535) {
      console.error(colors_default.red(`Error: Invalid port number: ${portValue}`));
      console.error(colors_default.blue("Port must be between 1 and 65535."));
      process.exit(1);
    }
    hasExplicitPort = true;
  }
  let tld;
  try {
    tld = getDefaultTld();
  } catch (err) {
    console.error(colors_default.red(`Error: ${err.message}`));
    process.exit(1);
  }
  const tldIdx = args.indexOf("--tld");
  if (tldIdx !== -1) {
    const tldValue = args[tldIdx + 1];
    if (!tldValue || tldValue.startsWith("-")) {
      console.error(colors_default.red("Error: --tld requires a TLD value (e.g. test, localhost)."));
      process.exit(1);
    }
    tld = tldValue.trim().toLowerCase();
    const tldErr = validateTld(tld);
    if (tldErr) {
      console.error(colors_default.red(`Error: ${tldErr}`));
      process.exit(1);
    }
  }
  const useWildcard = args.includes("--wildcard") || isWildcardEnvEnabled();
  const explicit = {
    useHttps: hasHttpsFlag || hasNoTls || customCertPath !== null || customKeyPath !== null || process.env.PORTLESS_HTTPS !== void 0,
    customCert: customCertPath !== null || customKeyPath !== null,
    lanMode: process.env.PORTLESS_LAN !== void 0,
    lanIp: process.env.PORTLESS_LAN_IP !== void 0,
    tld: tldIdx !== -1 || process.env.PORTLESS_TLD !== void 0,
    useWildcard: args.includes("--wildcard") || process.env.PORTLESS_WILDCARD !== void 0
  };
  let stateDir = resolveStateDir(proxyPort);
  let persistedLanMode = readLanMarker(stateDir) !== null;
  let runningPort = null;
  if (!hasExplicitPort) {
    const currentState = await discoverState();
    persistedLanMode = currentState.lanMode;
    if (await isProxyRunning(currentState.port) || !!process.env.PORTLESS_STATE_DIR && await isPortListening(currentState.port)) {
      runningPort = currentState.port;
      proxyPort = currentState.port;
      stateDir = currentState.dir;
    }
  }
  const desiredConfig = resolveProxyConfig({
    persistedLanMode,
    explicit,
    defaultTld: getDefaultTld(),
    useHttps: wantHttps || !!(customCertPath && customKeyPath),
    customCertPath,
    customKeyPath,
    lanMode: isLanEnvEnabled(),
    lanIp: process.env.PORTLESS_LAN_IP || null,
    tld,
    useWildcard
  });
  const lanMode = desiredConfig.lanMode;
  useHttps = desiredConfig.useHttps;
  customCertPath = desiredConfig.customCertPath;
  customKeyPath = desiredConfig.customKeyPath;
  tld = desiredConfig.tld;
  const desiredWildcard = desiredConfig.useWildcard;
  let lanIp = desiredConfig.lanIpExplicit ? desiredConfig.lanIp : null;
  if (!hasExplicitPort && runningPort === null) {
    proxyPort = getDefaultPort(useHttps);
    stateDir = resolveStateDir(proxyPort);
  }
  if (lanMode && tldIdx !== -1) {
    const userTld = args[tldIdx + 1];
    if (userTld && userTld !== "local") {
      console.warn(
        chalk.yellow(
          `Warning: --lan forces .local TLD (mDNS requirement). Ignoring --tld ${userTld}.`
        )
      );
    }
  }
  const riskyReason = RISKY_TLDS.get(tld);
  if (riskyReason && !lanMode) {
    console.warn(colors_default.yellow(`Warning: .${tld}: ${riskyReason}`));
  }
  const syncDisabled = process.env.PORTLESS_SYNC_HOSTS === "0" || process.env.PORTLESS_SYNC_HOSTS === "false";
  if (tld !== DEFAULT_TLD && !lanMode && syncDisabled) {
    console.warn(
      colors_default.yellow(
        `Warning: .${tld} domains require ${HOSTS_DISPLAY} entries to resolve to 127.0.0.1.`
      )
    );
    console.warn(colors_default.yellow("Hosts sync is disabled. To add entries manually, run:"));
    console.warn(colors_default.cyan("  portless hosts sync"));
  }
  let store = new RouteStore(stateDir, {
    onWarning: (msg) => console.warn(colors_default.yellow(msg))
  });
  const proxyRunning = runningPort !== null || await isProxyRunning(proxyPort);
  if (proxyRunning) {
    const runningConfig = readCurrentProxyConfig(stateDir);
    const mismatchMessages = getProxyConfigMismatchMessages(desiredConfig, runningConfig, explicit);
    if (mismatchMessages.length > 0) {
      printProxyConfigMismatch(proxyPort, desiredConfig, mismatchMessages);
    }
    if (isForeground) {
      return;
    }
    const portFlag = proxyPort !== getDefaultPort(useHttps) ? ` -p ${proxyPort}` : "";
    console.log(colors_default.yellow(`Proxy is already running on port ${proxyPort}.`));
    console.log(
      colors_default.blue(`To restart: portless proxy stop${portFlag} && portless proxy start${portFlag}`)
    );
    return;
  }
  if (lanMode) {
    const mdnsSupport = isMdnsSupported();
    if (!mdnsSupport.supported) {
      console.error(
        colors_default.red(
          "Error: LAN mode requires mDNS publishing, which is not supported on this platform."
        )
      );
      if (mdnsSupport.reason) {
        console.error(colors_default.gray(mdnsSupport.reason));
      }
      process.exit(1);
    }
    const inheritedLanIp = process.env[INTERNAL_LAN_IP_ENV] || null;
    delete process.env[INTERNAL_LAN_IP_ENV];
    if (!lanIp) {
      lanIp = inheritedLanIp || await getLocalNetworkIp();
    }
    if (!lanIp) {
      console.error(colors_default.red("Error: Could not detect LAN IP. Are you connected to a network?"));
      console.error(colors_default.blue("Specify manually:"));
      console.error(colors_default.cyan("  portless proxy start --lan --ip 192.168.1.42"));
      process.exit(1);
    }
  } else {
    delete process.env[INTERNAL_LAN_IP_ENV];
  }
  const resolvedConfig = {
    ...desiredConfig,
    useHttps,
    customCertPath,
    customKeyPath,
    lanMode,
    lanIp: desiredConfig.lanIpExplicit ? lanIp : null,
    lanIpExplicit: desiredConfig.lanIpExplicit,
    tld,
    useWildcard: desiredWildcard
  };
  if (!isWindows && proxyPort < PRIVILEGED_PORT_THRESHOLD && (process.getuid?.() ?? -1) !== 0) {
    const startArgs = [
      process.execPath,
      getEntryScript(),
      "proxy",
      "start",
      ...buildProxyStartConfig({
        useHttps,
        customCertPath,
        customKeyPath,
        lanMode,
        lanIp: desiredConfig.lanIpExplicit ? lanIp : null,
        lanIpExplicit: desiredConfig.lanIpExplicit,
        tld,
        useWildcard: desiredWildcard,
        foreground: isForeground,
        includePort: true,
        proxyPort
      }).args
    ];
    const fallbackCommand = formatProxyStartCommand(FALLBACK_PROXY_PORT, resolvedConfig);
    const currentCommand = formatProxyStartCommand(proxyPort, resolvedConfig);
    console.log(
      colors_default.yellow(`Port ${proxyPort} requires elevated privileges. Requesting sudo...`)
    );
    if (!hasExplicitPort) {
      console.log(colors_default.gray(`(To skip sudo, use an unprivileged port: ${fallbackCommand})`));
    }
    const result = spawnSync3("sudo", ["env", ...collectPortlessEnvArgs(), ...startArgs], {
      stdio: "inherit",
      timeout: SUDO_SPAWN_TIMEOUT_MS
    });
    if (result.status === 0) {
      if (!isForeground) {
        if (await waitForProxy(proxyPort)) {
          console.log(colors_default.green(`Proxy started on port ${proxyPort}.`));
        } else {
          console.error(colors_default.red("Proxy process started but is not responding."));
          const logPath2 = path8.join(resolveStateDir(proxyPort), "proxy.log");
          if (fs8.existsSync(logPath2)) {
            console.error(colors_default.gray(`Logs: ${logPath2}`));
          }
        }
      }
      return;
    }
    if (result.signal) {
      process.exit(1);
    }
    if (!hasExplicitPort) {
      proxyPort = FALLBACK_PROXY_PORT;
      console.log(colors_default.yellow(`Falling back to port ${proxyPort}.`));
      console.log(
        colors_default.blue(`For clean URLs without port numbers, re-run and accept the sudo prompt:`)
      );
      console.log(colors_default.cyan(`  ${fallbackCommand}`));
      if (await isProxyRunning(proxyPort)) {
        console.log(colors_default.yellow(`Proxy is already running on port ${proxyPort}.`));
        return;
      }
      stateDir = resolveStateDir(proxyPort);
      store = new RouteStore(stateDir, {
        onWarning: (msg) => console.warn(colors_default.yellow(msg))
      });
    } else {
      console.error(
        colors_default.red(`Error: Port ${proxyPort} requires elevated privileges and sudo failed.`)
      );
      console.error(colors_default.blue("Try again (portless will prompt for sudo):"));
      console.error(colors_default.cyan(`  ${currentCommand}`));
      process.exit(1);
    }
  }
  let tlsOptions;
  if (useHttps) {
    store.ensureDir();
    if (customCertPath && customKeyPath) {
      try {
        const cert = fs8.readFileSync(customCertPath);
        const key = fs8.readFileSync(customKeyPath);
        const certStr = cert.toString("utf-8");
        const keyStr = key.toString("utf-8");
        if (!certStr.includes("-----BEGIN CERTIFICATE-----")) {
          console.error(colors_default.red(`Error: ${customCertPath} is not a valid PEM certificate.`));
          console.error(colors_default.gray("Expected a file starting with -----BEGIN CERTIFICATE-----"));
          process.exit(1);
        }
        if (!keyStr.match(/-----BEGIN [\w\s]*PRIVATE KEY-----/)) {
          console.error(colors_default.red(`Error: ${customKeyPath} is not a valid PEM private key.`));
          console.error(
            colors_default.gray("Expected a file starting with -----BEGIN ...PRIVATE KEY-----")
          );
          process.exit(1);
        }
        tlsOptions = { cert, key };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(colors_default.red(`Error reading certificate files: ${message}`));
        process.exit(1);
      }
    } else {
      console.log(colors_default.gray("Ensuring TLS certificates..."));
      const certs = ensureCerts(stateDir);
      if (certs.caGenerated) {
        console.log(colors_default.green("Generated local CA certificate."));
      }
      if (!skipTrust && !isCATrusted(stateDir)) {
        console.log(colors_default.yellow("Adding CA to system trust store..."));
        const trustResult = trustCA(stateDir);
        if (trustResult.trusted) {
          console.log(
            colors_default.green("CA added to system trust store. Browsers will trust portless certs.")
          );
        } else {
          console.warn(colors_default.yellow("Could not add CA to system trust store."));
          if (trustResult.error) {
            console.warn(colors_default.gray(trustResult.error));
          }
          console.warn(
            colors_default.yellow("Browsers will show certificate warnings. To fix this later, run:")
          );
          console.warn(colors_default.cyan("  portless trust"));
        }
      }
      const cert = fs8.readFileSync(certs.certPath);
      const key = fs8.readFileSync(certs.keyPath);
      const ca = fs8.readFileSync(certs.caPath);
      tlsOptions = {
        cert,
        key,
        ca,
        SNICallback: createSNICallback(stateDir, cert, key, tld, ca)
      };
    }
  }
  if (isForeground) {
    console.log(chalk.blue.bold("\nportless proxy\n"));
    startProxyServer(store, proxyPort, tld, tlsOptions, lanIp, desiredWildcard ? false : void 0);
    return;
  }
  store.ensureDir();
  const logPath = path8.join(stateDir, "proxy.log");
  const logFd = fs8.openSync(logPath, "a");
  try {
    try {
      fs8.chmodSync(logPath, FILE_MODE);
    } catch {
    }
    fixOwnership(logPath);
    const daemonArgs = [
      getEntryScript(),
      "proxy",
      "start",
      ...buildProxyStartConfig({
        useHttps,
        customCertPath,
        customKeyPath,
        lanMode,
        lanIp: desiredConfig.lanIpExplicit ? lanIp : null,
        lanIpExplicit: desiredConfig.lanIpExplicit,
        tld,
        useWildcard: desiredWildcard,
        foreground: true,
        includePort: true,
        proxyPort,
        skipTrust: true
      }).args
    ];
    const child = spawn3(process.execPath, daemonArgs, {
      detached: true,
      stdio: ["ignore", logFd, logFd],
      env: process.env,
      windowsHide: true
    });
    child.unref();
  } finally {
    fs8.closeSync(logFd);
  }
  if (!await waitForProxy(proxyPort, void 0, void 0, useHttps)) {
    console.error(colors_default.red("Proxy failed to start (timed out waiting for it to listen)."));
    console.error(colors_default.blue("Try starting the proxy in the foreground to see the error:"));
    console.error(colors_default.cyan("  portless proxy start --foreground"));
    if (fs8.existsSync(logPath)) {
      console.error(colors_default.gray(`Logs: ${logPath}`));
    }
    process.exit(1);
  }
  const proto = useHttps ? "HTTPS/2" : "HTTP";
  console.log(chalk.green(`${proto} proxy started on port ${proxyPort}`));
  if (lanMode && lanIp) {
    console.log(chalk.green(`LAN mode active. IP: ${lanIp}`));
    console.log(chalk.gray("Services will be discoverable as <name>.local on your network."));
  }
}
function loadAppConfig(cwd = process.cwd()) {
  try {
    const loaded = loadConfig(cwd);
    if (!loaded) return null;
    return resolveAppConfig(loaded.config, loaded.configDir, cwd);
  } catch (err) {
    if (err instanceof ConfigValidationError) {
      console.error(colors_default.red(`Error: ${err.message}`));
      process.exit(1);
    }
    throw err;
  }
}
async function handleDefaultMode(globalScript, extraArgs = []) {
  const cwd = process.cwd();
  const wsRoot = findWorkspaceRoot(cwd);
  if (wsRoot === cwd) {
    const packages = discoverWorkspacePackages(cwd);
    let wsScriptName;
    try {
      wsScriptName = globalScript ?? loadConfig(cwd)?.config.script ?? "dev";
    } catch (err) {
      if (err instanceof ConfigValidationError) {
        console.error(colors_default.red(`Error: ${err.message}`));
        process.exit(1);
      }
      throw err;
    }
    const hasMatchingPackages = packages.some((p) => p.scripts[wsScriptName]);
    if (hasMatchingPackages) {
      await handleDefaultMulti(cwd, globalScript, extraArgs);
      return true;
    }
  }
  const appConfig = loadAppConfig(cwd);
  const scriptName = globalScript ?? appConfig?.script ?? "dev";
  if (hasScript(scriptName, cwd)) {
    await handleDefaultSingle(cwd, scriptName, appConfig);
    return true;
  }
  return false;
}
async function handleDefaultSingle(cwd, scriptName, appConfig) {
  const resolved = resolveScriptCommand(scriptName, cwd);
  if (!resolved) {
    console.error(colors_default.red(`Error: No "${scriptName}" script found in package.json.`));
    process.exit(1);
  }
  let baseName;
  let nameSource;
  if (appConfig?.name) {
    baseName = appConfig.name.split(".").map((label) => truncateLabel(label)).join(".");
    nameSource = "portless.json";
  } else {
    const inferred = inferProjectName(cwd);
    baseName = inferred.name;
    nameSource = inferred.source;
  }
  const worktree = detectWorktreePrefix(cwd);
  const effectiveName = worktree ? `${worktree.prefix}.${baseName}` : baseName;
  const { dir, port, tls: tls2, tld, lanMode, lanIp } = await discoverState();
  const store = new RouteStore(dir, {
    onWarning: (msg) => console.warn(colors_default.yellow(msg))
  });
  await runApp(
    store,
    port,
    dir,
    effectiveName,
    resolved,
    tls2,
    tld,
    false,
    { nameSource, prefix: worktree?.prefix, prefixSource: worktree?.source },
    appConfig?.appPort,
    lanMode,
    lanIp
  );
}
function spawnChildProcess(commandArgs, env, cwd) {
  return spawn3(commandArgs[0], commandArgs.slice(1), {
    stdio: ["ignore", "pipe", "pipe"],
    env,
    cwd,
    ...isWindows ? {} : { detached: true }
  });
}
function prefixStream(stream, output, prefix) {
  if (!stream) return;
  const decoder = new StringDecoder("utf8");
  let buffer = "";
  stream.on("data", (data) => {
    buffer += decoder.write(data);
    let idx;
    while ((idx = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, idx).replace(/\r$/, "");
      buffer = buffer.slice(idx + 1);
      output.write(`${prefix} ${line}
`);
    }
  });
  stream.on("end", () => {
    buffer += decoder.end();
    if (buffer) output.write(`${prefix} ${buffer}
`);
  });
}
function pipeOutput(child, prefix) {
  prefixStream(child.stdout, process.stdout, prefix);
  prefixStream(child.stderr, process.stderr, prefix);
}
async function spawnProxiedApp(app, stateDir, proxyPort, tls2, tld, exitCodes) {
  const usesPortless = app.commandArgs[0] === "portless";
  const pkgEnv = { ...process.env };
  pkgEnv.PATH = augmentedPath(pkgEnv, app.pkg.dir);
  let env;
  let store = null;
  let hostname = null;
  let displayUrl;
  if (usesPortless) {
    env = pkgEnv;
    displayUrl = "(managed by portless)";
  } else {
    store = new RouteStore(stateDir, {
      onWarning: (msg) => console.warn(colors_default.yellow(`[${app.name}] ${msg}`))
    });
    const appPort = app.appPort ?? await findFreePort();
    const protocol = tls2 ? "https" : "http";
    const portSuffix = tls2 && proxyPort === 443 || !tls2 && proxyPort === 80 ? "" : `:${proxyPort}`;
    const url = `${protocol}://${app.name}.${tld}${portSuffix}`;
    displayUrl = url;
    hostname = parseHostname(app.name, tld);
    store.addRoute(hostname, appPort, process.pid);
    env = {
      ...pkgEnv,
      PORT: String(appPort),
      HOST: "127.0.0.1",
      PORTLESS_URL: url
    };
    if (tls2) {
      const caPath = path8.join(stateDir, "ca.pem");
      if (fs8.existsSync(caPath)) {
        env.NODE_EXTRA_CA_CERTS = caPath;
      }
    }
  }
  const child = spawnChildProcess(app.commandArgs, env, app.pkg.dir);
  pipeOutput(child, chalk.cyan(`[${app.name}]`));
  const capturedStore = store;
  const capturedHostname = hostname;
  child.on("exit", (code, signal) => {
    exitCodes.set(app.name, code);
    if (code !== 0 && code !== null) {
      console.error(colors_default.red(`[${app.name}] exited with code ${code}`));
    } else if (signal) {
      console.error(colors_default.yellow(`[${app.name}] killed by ${signal}`));
    }
    if (capturedStore && capturedHostname) {
      try {
        capturedStore.removeRoute(capturedHostname);
      } catch {
      }
    }
  });
  const route = store && hostname ? { store, hostname } : null;
  return { child, displayUrl, route };
}
function spawnTaskApp(app, exitCodes) {
  const pkgEnv = { ...process.env };
  pkgEnv.PATH = augmentedPath(pkgEnv, app.pkg.dir);
  const child = spawnChildProcess(app.commandArgs, pkgEnv, app.pkg.dir);
  pipeOutput(child, chalk.gray(`[${app.name}]`));
  child.on("exit", (code, signal) => {
    exitCodes.set(app.name, code);
    if (code !== 0 && code !== null) {
      console.error(colors_default.red(`[${app.name}] exited with code ${code}`));
    } else if (signal) {
      console.error(colors_default.yellow(`[${app.name}] killed by ${signal}`));
    }
  });
  return child;
}
async function handleDefaultMulti(wsRoot, globalScript, extraArgs = []) {
  let loaded;
  try {
    loaded = loadConfig(wsRoot);
  } catch (err) {
    if (err instanceof ConfigValidationError) {
      console.error(colors_default.red(`Error: ${err.message}`));
      process.exit(1);
    }
    throw err;
  }
  const packages = discoverWorkspacePackages(wsRoot);
  if (packages.length === 0) {
    console.error(colors_default.red("Error: No workspace packages found."));
    process.exit(1);
  }
  const scriptName = globalScript ?? loaded?.config.script ?? "dev";
  let projectName;
  if (loaded?.config.name) {
    projectName = loaded.config.name.split(".").map((label) => truncateLabel(label)).join(".");
  } else {
    const scopeCounts = /* @__PURE__ */ new Map();
    for (const p of packages) {
      if (p.scope) scopeCounts.set(p.scope, (scopeCounts.get(p.scope) ?? 0) + 1);
    }
    let commonScope;
    let maxCount = 0;
    for (const [scope, count] of scopeCounts) {
      if (count > maxCount) {
        commonScope = scope;
        maxCount = count;
      }
    }
    if (commonScope) {
      projectName = sanitizeForHostname(commonScope) || inferProjectName(wsRoot).name;
    } else {
      projectName = inferProjectName(wsRoot).name;
    }
  }
  const apps = [];
  for (const pkg of packages) {
    const rel = path8.relative(wsRoot, pkg.dir).replace(/\\/g, "/");
    const rootOverride = loaded ? resolveAppConfig(loaded.config, loaded.configDir, pkg.dir) : null;
    let pkgConfig;
    try {
      pkgConfig = loadPackagePortlessConfig(pkg.dir);
    } catch (err) {
      if (err instanceof ConfigValidationError) {
        console.error(colors_default.red(`Error: ${err.message}`));
        process.exit(1);
      }
      throw err;
    }
    const appOverride = {
      ...Object.fromEntries(Object.entries(rootOverride ?? {}).filter(([, v]) => v !== void 0)),
      ...Object.fromEntries(Object.entries(pkgConfig ?? {}).filter(([, v]) => v !== void 0))
    };
    const effectiveScript = appOverride.script ?? scriptName;
    const scriptValue = pkg.scripts[effectiveScript];
    if (!scriptValue) continue;
    const rawScript = splitCommand(scriptValue);
    if (rawScript.length === 0) continue;
    const pm = detectPackageManager(pkg.dir);
    const commandArgs = [pm, "run", effectiveScript];
    const proxied = appOverride.proxy ?? isServerCommand(rawScript);
    let name;
    let label;
    if (appOverride.name) {
      name = appOverride.name.split(".").map((l) => truncateLabel(l)).join(".");
      label = appOverride.name;
    } else {
      let pkgLabel;
      if (pkg.name) {
        const sanitized = sanitizeForHostname(pkg.name);
        pkgLabel = sanitized || rel.replace(/\//g, "-");
      } else {
        pkgLabel = rel.replace(/\//g, "-");
      }
      name = pkgLabel === projectName ? projectName : `${pkgLabel}.${projectName}`;
      label = pkg.scope ? `@${pkg.scope}/${pkg.name}` : pkg.name ?? rel;
    }
    apps.push({ pkg, name, label, commandArgs, appPort: appOverride.appPort, proxied });
  }
  if (apps.length === 0) {
    console.error(colors_default.yellow(`No workspace packages have a "${scriptName}" script.`));
    process.exit(1);
  }
  apps.sort((a, b) => a.label.localeCompare(b.label));
  const proxiedApps = apps.filter((a) => a.proxied);
  const taskApps = apps.filter((a) => !a.proxied);
  console.log(chalk.blue.bold(`
portless
`));
  let { dir, port, tls: tls2, tld } = await discoverState();
  if (proxiedApps.length > 0) {
    let multiDesired;
    try {
      multiDesired = resolveProxyDesiredState(false);
    } catch (err) {
      console.error(colors_default.red(`Error: ${err.message}`));
      process.exit(1);
    }
    const ensureResult = await ensureProxyRunning(port, tls2, multiDesired);
    if (ensureResult.started) {
      dir = ensureResult.state.dir;
      port = ensureResult.state.port;
      tls2 = ensureResult.state.tls;
      tld = ensureResult.state.tld;
    } else {
      ({ dir, port, tls: tls2, tld } = await discoverState());
    }
    if (tls2 && !isCATrusted(dir)) {
      await handleTrust();
    }
  }
  const useTurbo = loaded?.config.turbo !== false && hasTurboConfig(wsRoot);
  if (useTurbo) {
    await runWithTurbo(wsRoot, dir, port, tls2, tld, scriptName, proxiedApps, taskApps, extraArgs);
  } else {
    await runWithDirectSpawn(dir, port, tls2, tld, proxiedApps, taskApps);
  }
}
async function runWithTurbo(wsRoot, stateDir, proxyPort, tls2, tld, scriptName, proxiedApps, taskApps, extraArgs = []) {
  const store = new RouteStore(stateDir, {
    onWarning: (msg) => console.warn(colors_default.yellow(msg))
  });
  const manifest = {};
  const routes = [];
  const appUrls = [];
  for (const app of proxiedApps) {
    const usesPortless = app.commandArgs[0] === "portless";
    if (usesPortless) {
      appUrls.push({ label: app.label, url: "(managed by portless)" });
      continue;
    }
    const appPort = app.appPort ?? await findFreePort();
    const protocol = tls2 ? "https" : "http";
    const portSuffix = tls2 && proxyPort === 443 || !tls2 && proxyPort === 80 ? "" : `:${proxyPort}`;
    const url = `${protocol}://${app.name}.${tld}${portSuffix}`;
    appUrls.push({ label: app.label, url });
    const hostname = parseHostname(app.name, tld);
    store.addRoute(hostname, appPort, process.pid);
    routes.push({ hostname });
    const entry = {
      PORT: String(appPort),
      HOST: "127.0.0.1",
      PORTLESS_URL: url
    };
    if (tls2) {
      const caPath = path8.join(stateDir, "ca.pem");
      if (fs8.existsSync(caPath)) {
        entry.NODE_EXTRA_CA_CERTS = caPath;
      }
    }
    manifest[app.pkg.dir] = entry;
  }
  ensureEnvLoader();
  writeManifest(manifest);
  if (appUrls.length > 0) {
    const maxLabel = Math.max(...appUrls.map((a) => a.label.length));
    for (const { label, url } of appUrls) {
      const pad = " ".repeat(maxLabel - label.length);
      console.log(`  ${label}${pad}  ${chalk.dim(url)}`);
    }
  }
  console.log("");
  const pm = detectPackageManager(wsRoot);
  const useRootScript = hasScript(scriptName, wsRoot);
  const turboArgs = useRootScript ? [pm, "run", scriptName, ...extraArgs] : pm === "npm" ? ["npx", "turbo", "run", scriptName, ...extraArgs] : pm === "bun" ? ["bunx", "turbo", "run", scriptName, ...extraArgs] : [pm, "exec", "turbo", "run", scriptName, ...extraArgs];
  const turboChild = spawn3(turboArgs[0], turboArgs.slice(1), {
    stdio: "inherit",
    cwd: wsRoot,
    env: {
      ...process.env,
      NODE_OPTIONS: buildNodeOptions()
    },
    ...isWindows ? {} : { detached: true }
  });
  const SIGKILL_TIMEOUT_MS = 5e3;
  let cleanedUp = false;
  const cleanup = () => {
    if (cleanedUp) return;
    cleanedUp = true;
    killTree(turboChild, "SIGTERM");
    setTimeout(() => {
      if (turboChild.exitCode === null && !turboChild.killed) {
        killTree(turboChild, "SIGKILL");
      }
    }, SIGKILL_TIMEOUT_MS).unref();
    for (const { hostname } of routes) {
      try {
        store.removeRoute(hostname);
      } catch {
      }
    }
    removeManifest();
  };
  process.on("SIGINT", cleanup);
  process.on("SIGTERM", cleanup);
  const exitCode = await new Promise((resolve3) => {
    turboChild.on("exit", (code) => resolve3(code));
  });
  cleanup();
  if (exitCode !== 0 && exitCode !== null) {
    process.exit(exitCode);
  }
}
async function runWithDirectSpawn(stateDir, proxyPort, tls2, tld, proxiedApps, taskApps) {
  const children = [];
  const exitCodes = /* @__PURE__ */ new Map();
  const appUrls = [];
  const routeEntries = [];
  for (const app of proxiedApps) {
    const { child, displayUrl, route } = await spawnProxiedApp(
      app,
      stateDir,
      proxyPort,
      tls2,
      tld,
      exitCodes
    );
    children.push(child);
    if (route) routeEntries.push(route);
    appUrls.push({ label: app.label, url: displayUrl });
  }
  const taskLabels = [];
  for (const app of taskApps) {
    children.push(spawnTaskApp(app, exitCodes));
    taskLabels.push(app.label);
  }
  if (appUrls.length > 0) {
    const maxLabel = Math.max(...appUrls.map((a) => a.label.length));
    for (const { label, url } of appUrls) {
      const pad = " ".repeat(maxLabel - label.length);
      console.log(`  ${label}${pad}  ${chalk.dim(url)}`);
    }
  }
  console.log("");
  const SIGKILL_TIMEOUT_MS = 5e3;
  let cleanedUp = false;
  const cleanup = () => {
    if (cleanedUp) return;
    cleanedUp = true;
    for (const child of children) {
      killTree(child, "SIGTERM");
    }
    setTimeout(() => {
      for (const child of children) {
        if (child.exitCode === null && !child.killed) {
          killTree(child, "SIGKILL");
        }
      }
    }, SIGKILL_TIMEOUT_MS).unref();
    for (const { store, hostname } of routeEntries) {
      try {
        store.removeRoute(hostname);
      } catch {
      }
    }
  };
  process.on("SIGINT", cleanup);
  process.on("SIGTERM", cleanup);
  await Promise.all(
    children.map(
      (child) => new Promise((resolve3) => {
        child.on("exit", () => resolve3());
      })
    )
  );
  const failed = [...exitCodes.entries()].filter(([, code]) => code !== 0 && code !== null);
  if (failed.length > 0) {
    console.error(
      colors_default.red(
        `
${failed.length} app${failed.length === 1 ? "" : "s"} exited with errors: ${failed.map(([name, code]) => `${name} (${code})`).join(", ")}`
      )
    );
    process.exit(1);
  }
}
async function handleRunMode(args, globalScript) {
  const parsed = parseRunArgs(args);
  const appConfig = loadAppConfig();
  if (parsed.commandArgs.length === 0) {
    const scriptName = globalScript ?? appConfig?.script ?? "dev";
    const resolved = resolveScriptCommand(scriptName, process.cwd());
    if (resolved) {
      parsed.commandArgs = resolved;
    }
  }
  if (parsed.commandArgs.length === 0) {
    console.error(colors_default.red("Error: No command provided."));
    console.error(colors_default.blue("Usage:"));
    console.error(colors_default.cyan("  portless run <command...>"));
    console.error(colors_default.blue("Example:"));
    console.error(colors_default.cyan("  portless run next dev"));
    process.exit(1);
  }
  let baseName;
  let nameSource;
  if (parsed.name) {
    baseName = parsed.name.split(".").map((label) => truncateLabel(label)).join(".");
    nameSource = "--name flag";
  } else if (appConfig?.name) {
    baseName = appConfig.name.split(".").map((label) => truncateLabel(label)).join(".");
    nameSource = "portless.json";
  } else {
    const inferred = inferProjectName();
    baseName = inferred.name;
    nameSource = inferred.source;
  }
  if (!parsed.appPort && appConfig?.appPort) {
    parsed.appPort = appConfig.appPort;
  }
  const worktree = detectWorktreePrefix();
  const effectiveName = worktree ? `${worktree.prefix}.${baseName}` : baseName;
  const { dir, port, tls: tls2, tld, lanMode, lanIp } = await discoverState();
  const store = new RouteStore(dir, {
    onWarning: (msg) => console.warn(colors_default.yellow(msg))
  });
  await runApp(
    store,
    port,
    dir,
    effectiveName,
    parsed.commandArgs,
    tls2,
    tld,
    parsed.force,
    { nameSource, prefix: worktree?.prefix, prefixSource: worktree?.source },
    parsed.appPort,
    lanMode,
    lanIp
  );
}
async function handleNamedMode(args) {
  const parsed = parseAppArgs(args);
  if (parsed.commandArgs.length === 0) {
    console.error(colors_default.red("Error: No command provided."));
    console.error(colors_default.blue("Usage:"));
    console.error(colors_default.cyan("  portless <name> <command...>"));
    console.error(colors_default.blue("Example:"));
    console.error(colors_default.cyan("  portless myapp next dev"));
    process.exit(1);
  }
  if (!parsed.appPort) {
    const appConfig = loadAppConfig();
    if (appConfig?.appPort) {
      parsed.appPort = appConfig.appPort;
    }
  }
  const safeName = parsed.name.split(".").map((label) => truncateLabel(label)).join(".");
  const { dir, port, tls: tls2, tld, lanMode, lanIp } = await discoverState();
  const store = new RouteStore(dir, {
    onWarning: (msg) => console.warn(colors_default.yellow(msg))
  });
  await runApp(
    store,
    port,
    dir,
    safeName,
    parsed.commandArgs,
    tls2,
    tld,
    parsed.force,
    void 0,
    parsed.appPort,
    lanMode,
    lanIp
  );
}
async function main() {
  if (process.stdin.isTTY) {
    process.on("exit", () => {
      try {
        process.stdin.setRawMode(false);
      } catch {
      }
    });
  }
  const args = process.argv.slice(2);
  const isNpx = process.env.npm_command === "exec" && !process.env.npm_lifecycle_event;
  const isPnpmDlx = !!process.env.PNPM_SCRIPT_SRC_DIR && !process.env.npm_lifecycle_event;
  if ((isNpx || isPnpmDlx) && !isLocallyInstalled()) {
    console.error(colors_default.red("Error: portless should not be run via npx or pnpm dlx."));
    console.error(colors_default.blue("Install globally or as a project dependency:"));
    console.error(colors_default.cyan("  npm install -g portless"));
    console.error(colors_default.cyan("  npm install -D portless"));
    process.exit(1);
  }
  const stripGlobalFlag = (flag, hasValue) => {
    const sep = args.indexOf("--");
    const end = sep === -1 ? args.length : sep;
    const idx = args.indexOf(flag);
    if (idx === -1 || idx >= end) return null;
    if (!hasValue) {
      args.splice(idx, 1);
      return true;
    }
    const value = args[idx + 1];
    if (!value || value.startsWith("-")) return false;
    args.splice(idx, 2);
    return value;
  };
  if (stripGlobalFlag("--lan", false)) {
    process.env.PORTLESS_LAN = "1";
  }
  const ipResult = stripGlobalFlag("--ip", true);
  if (ipResult === false) {
    console.error(chalk.red("Error: --ip requires an IP address."));
    console.error(chalk.cyan("  portless --lan --ip 192.168.1.42 run <command>"));
    process.exit(1);
  } else if (typeof ipResult === "string") {
    process.env.PORTLESS_LAN_IP = ipResult;
    process.env.PORTLESS_LAN = "1";
  }
  const autoIpResult = stripGlobalFlag(INTERNAL_LAN_IP_FLAG, true);
  if (autoIpResult === false) {
    console.error(chalk.red(`Error: ${INTERNAL_LAN_IP_FLAG} requires an IP address.`));
    process.exit(1);
  } else if (typeof autoIpResult === "string") {
    process.env[INTERNAL_LAN_IP_ENV] = autoIpResult;
    process.env.PORTLESS_LAN = "1";
  }
  if (stripGlobalFlag("--tailscale", false)) {
    process.env.PORTLESS_TAILSCALE = "1";
  }
  if (stripGlobalFlag("--funnel", false)) {
    process.env.PORTLESS_FUNNEL = "1";
    process.env.PORTLESS_TAILSCALE = "1";
  }
  const scriptResult = stripGlobalFlag("--script", true);
  if (scriptResult === false) {
    console.error(colors_default.red("Error: --script requires a script name."));
    console.error(colors_default.cyan("  portless --script start"));
    process.exit(1);
  }
  const globalScript = typeof scriptResult === "string" ? scriptResult : void 0;
  if (args[0] === "--name") {
    args.shift();
    if (!args[0]) {
      console.error(colors_default.red("Error: --name requires an app name."));
      console.error(colors_default.cyan("  portless --name <name> <command...>"));
      process.exit(1);
    }
    const skipPortless2 = process.env.PORTLESS === "0" || process.env.PORTLESS === "false" || process.env.PORTLESS === "skip";
    if (skipPortless2) {
      const { commandArgs } = parseAppArgs(args);
      if (commandArgs.length === 0) {
        console.error(colors_default.red("Error: No command provided."));
        process.exit(1);
      }
      spawnCommand(commandArgs);
      return;
    }
    await handleNamedMode(args);
    return;
  }
  const isRunCommand = args[0] === "run";
  if (isRunCommand) {
    args.shift();
  }
  const skipPortless = process.env.PORTLESS === "0" || process.env.PORTLESS === "false" || process.env.PORTLESS === "skip";
  if (skipPortless && (isRunCommand || args.length === 0 || args.length >= 2 && args[0] !== "proxy" && args[0] !== "clean")) {
    const parsed = isRunCommand ? parseRunArgs(args) : parseAppArgs(args);
    let commandArgs = parsed.commandArgs;
    if (commandArgs.length === 0 && (isRunCommand || args.length === 0)) {
      const appConfig = loadAppConfig();
      const scriptName = globalScript ?? appConfig?.script ?? "dev";
      const resolved = resolveScriptCommand(scriptName, process.cwd());
      if (resolved) commandArgs = resolved;
    }
    if (commandArgs.length === 0) {
      console.error(colors_default.red("Error: No command provided."));
      process.exit(1);
    }
    spawnCommand(commandArgs);
    return;
  }
  if (!isRunCommand) {
    if (args[0] === "--help" || args[0] === "-h") {
      printHelp();
      return;
    }
    if (args.length === 0 || args[0] === "--") {
      const extraArgs = args[0] === "--" ? args.slice(1) : [];
      const handled = await handleDefaultMode(globalScript, extraArgs);
      if (handled) return;
      printHelp();
      return;
    }
    if (args[0] === "--version" || args[0] === "-v") {
      printVersion();
      return;
    }
    if (args[0] === "trust") {
      await handleTrust();
      return;
    }
    if (args[0] === "clean") {
      await handleClean(args);
      return;
    }
    if (args[0] === "prune") {
      await handlePrune(args);
      return;
    }
    if (args[0] === "list") {
      await handleList();
      return;
    }
    if (args[0] === "get") {
      await handleGet(args);
      return;
    }
    if (args[0] === "alias") {
      await handleAlias(args);
      return;
    }
    if (args[0] === "hosts") {
      await handleHosts(args);
      return;
    }
    if (args[0] === "proxy") {
      await handleProxy(args);
      return;
    }
  }
  if (isRunCommand) {
    await handleRunMode(args, globalScript);
  } else {
    await handleNamedMode(args);
  }
}
main().catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  console.error(colors_default.red("Error:"), message);
  process.exit(1);
});
