import { useState, useCallback, useRef, useEffect, useMemo } from "react";
import { generateCloudInit } from "./cloudInitGenerator";

// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────────────────────────────────────
const HETZNER_API = "https://api.hetzner.cloud/v1";

const STEPS = [
  { id: "welcome", label: "Welcome" },
  { id: "credentials", label: "API Key" },
  { id: "configure", label: "Configure" },
  { id: "review", label: "Review" },
  { id: "deploy", label: "Deploy" },
  { id: "complete", label: "Complete" },
];

const LOCATIONS = [
  { id: "fsn1", name: "Falkenstein", flag: "🇩🇪" },
  { id: "nbg1", name: "Nuremberg", flag: "🇩🇪" },
  { id: "hel1", name: "Helsinki", flag: "🇫🇮" },
  { id: "ash", name: "Ashburn", flag: "🇺🇸" },
  { id: "hil", name: "Hillsboro", flag: "🇺🇸" },
];

const SERVER_TYPES = [
  { id: "cx23", cpu: "2 vCPU", ram: "4 GB", disk: "40 GB", price: 5.39, rec: false },
  { id: "cx33", cpu: "4 vCPU", ram: "8 GB", disk: "80 GB", price: 8.49, rec: true },
  { id: "cx43", cpu: "8 vCPU", ram: "16 GB", disk: "160 GB", price: 16.49, rec: false },
  { id: "cx53", cpu: "16 vCPU", ram: "32 GB", disk: "320 GB", price: 31.49, rec: false },
];


// ─────────────────────────────────────────────────────────────────────────────
// CRYPTO UTILITIES — all secrets generated client-side
// ─────────────────────────────────────────────────────────────────────────────
const hex = (n) => {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return [...a].map((b) => b.toString(16).padStart(2, "0")).join("");
};

const BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Encode(bytes) {
  let bits = 0, value = 0, out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) { out += BASE32_CHARS[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += BASE32_CHARS[(value << (5 - bits)) & 31];
  return out;
}

const b64url = (str) =>
  btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const textToB64url = (text) => b64url(text);

async function hmacSha256(key, data) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function generateJwt(secret, role) {
  const header = textToB64url('{"typ":"JWT","alg":"HS256"}');
  const now = Math.floor(Date.now() / 1000);
  const exp = now + 5 * 365 * 24 * 3600;
  const payload = textToB64url(
    JSON.stringify({ iat: now, exp, iss: "supabase", role })
  );
  const sig = await hmacSha256(secret, `${header}.${payload}`);
  return `${header}.${payload}.${sig}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// SSH KEY GENERATION — ed25519 keypair generated entirely in the browser
// Outputs proper OpenSSH format compatible with all SSH clients.
// ─────────────────────────────────────────────────────────────────────────────

// Helper: write a uint32 big-endian into a Uint8Array
function sshUint32(value) {
  const buf = new Uint8Array(4);
  new DataView(buf.buffer).setUint32(0, value);
  return buf;
}

// Helper: write an SSH "string" (4-byte length prefix + data)
function sshString(data) {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const result = new Uint8Array(4 + bytes.length);
  new DataView(result.buffer).setUint32(0, bytes.length);
  result.set(bytes, 4);
  return result;
}

// Helper: concatenate multiple Uint8Arrays
function concatBytes(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) { result.set(a, offset); offset += a.length; }
  return result;
}

async function generateSshKeypair(serverName) {
  const keyPair = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"]
  );

  const [pkcs8Raw, publicRaw] = await Promise.all([
    crypto.subtle.exportKey("pkcs8", keyPair.privateKey),
    crypto.subtle.exportKey("raw", keyPair.publicKey),
  ]);

  const pubBytes = new Uint8Array(publicRaw); // 32 bytes
  // Extract 32-byte seed from PKCS#8 DER (always at byte offset 16 for ed25519)
  const seed = new Uint8Array(pkcs8Raw).slice(16, 48);
  const comment = `${serverName}-deploy`;

  // ── Public key in OpenSSH wire format ──
  const pubWire = concatBytes(sshString("ssh-ed25519"), sshString(pubBytes));
  const publicKeyStr = `ssh-ed25519 ${btoa(String.fromCharCode(...pubWire))} ${comment}`;

  // ── Private key in OpenSSH format ──
  // See: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
  const authMagic = new TextEncoder().encode("openssh-key-v1\0");

  // Private section: checkint(x2) + keytype + pub + priv(seed+pub) + comment + padding
  const checkInt = new Uint8Array(4);
  crypto.getRandomValues(checkInt);
  const privKeyData = concatBytes(seed, pubBytes); // 64 bytes (OpenSSH ed25519 format)

  const privPayload = concatBytes(
    checkInt, checkInt,
    sshString("ssh-ed25519"),
    sshString(pubBytes),
    sshString(privKeyData),
    sshString(comment),
  );
  // Pad to 8-byte alignment (padding bytes = 1, 2, 3, ...)
  const padLen = (8 - (privPayload.length % 8)) % 8;
  const padding = new Uint8Array(padLen);
  for (let i = 0; i < padLen; i++) padding[i] = i + 1;

  const privSection = concatBytes(privPayload, padding);

  // Full key blob
  const keyBlob = concatBytes(
    authMagic,
    sshString("none"),       // cipher
    sshString("none"),       // kdf
    sshString(new Uint8Array(0)), // kdf options
    sshUint32(1),            // number of keys
    sshString(pubWire),      // public key
    sshString(privSection),  // private section
  );

  const b64 = btoa(String.fromCharCode(...keyBlob));
  const lines = b64.match(/.{1,70}/g).join("\n");
  const privateKeyStr = `-----BEGIN OPENSSH PRIVATE KEY-----\n${lines}\n-----END OPENSSH PRIVATE KEY-----\n`;

  return { publicKey: publicKeyStr, privateKey: privateKeyStr };
}

async function generateAllSecrets() {
  const jwtSecret = hex(20);
  const totpRaw = new Uint8Array(20);
  crypto.getRandomValues(totpRaw);
  const [anonKey, serviceRoleKey] = await Promise.all([
    generateJwt(jwtSecret, "anon"),
    generateJwt(jwtSecret, "service_role"),
  ]);
  return {
    jwtSecret,
    anonKey,
    serviceRoleKey,
    postgresPassword: hex(16),
    secretKeyBase: hex(32),
    vaultEncKey: hex(16),
    pgMetaCryptoKey: hex(16),
    s3AccessKeyId: hex(16),
    s3AccessKeySecret: hex(32),
    minioRootPassword: hex(16),
    logflarePublicToken: hex(16),
    logflarePrivateToken: hex(16),
    autheliaSessionSecret: hex(32),
    autheliaStorageEncKey: hex(32),
    autheliaJwtSecret: hex(32),
    resticPassword: hex(24),
    totpSecret: base32Encode(totpRaw),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// HETZNER API CLIENT — all calls go directly to api.hetzner.cloud
// ─────────────────────────────────────────────────────────────────────────────
class HetznerClient {
  constructor(token) {
    this.token = token;
  }

  async request(method, path, body) {
    const res = await fetch(`${HETZNER_API}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${this.token}`,
        "Content-Type": "application/json",
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data?.error?.message || `API error ${res.status}`);
    return data;
  }

  async validateToken() {
    const data = await this.request("GET", "/servers?per_page=1");
    return !!data.servers;
  }

  async listSshKeys() {
    const data = await this.request("GET", "/ssh_keys");
    return data.ssh_keys || [];
  }

  async createSshKey(name, publicKey) {
    const data = await this.request("POST", "/ssh_keys", {
      name, public_key: publicKey,
    });
    return data.ssh_key;
  }

  async createFirewall(name) {
    const data = await this.request("POST", "/firewalls", {
      name,
      rules: [
        { direction: "in", protocol: "tcp", port: "22", source_ips: ["0.0.0.0/0", "::/0"], description: "SSH" },
        { direction: "in", protocol: "tcp", port: "80", source_ips: ["0.0.0.0/0", "::/0"], description: "HTTP" },
        { direction: "in", protocol: "tcp", port: "443", source_ips: ["0.0.0.0/0", "::/0"], description: "HTTPS" },
        { direction: "in", protocol: "udp", port: "443", source_ips: ["0.0.0.0/0", "::/0"], description: "QUIC" },
      ],
    });
    return data.firewall;
  }

  async createServer({ name, serverType, location, sshKeyIds, firewallIds, userData }) {
    const data = await this.request("POST", "/servers", {
      name,
      server_type: serverType,
      location,
      image: "ubuntu-24.04",
      ssh_keys: sshKeyIds,
      firewalls: firewallIds.map((id) => ({ firewall: id })),
      user_data: userData,
      public_net: { enable_ipv4: true, enable_ipv6: true },
      start_after_create: true,
    });
    return { server: data.server, action: data.action, rootPassword: data.root_password };
  }

  async getServer(id) {
    const data = await this.request("GET", `/servers/${id}`);
    return data.server;
  }

  async getServerLabels(id) {
    const server = await this.getServer(id);
    return server.labels || {};
  }

  async updateServerLabels(id, labels) {
    const data = await this.request("PUT", `/servers/${id}`, { labels });
    return data.server;
  }

  // Poll server labels for deployment status updates written by cloud-init
  async pollDeployStatus(serverId, onStatus, signal) {
    const PHASE_MAP = {
      provisioning: { label: "Server provisioned, waiting for boot...", pct: 40 },
      starting: { label: "Cloud-init starting...", pct: 42 },
      hardening: { label: "Waiting for apt lock & updating packages...", pct: 44 },
      packages_done: { label: "Packages installed, creating deploy user...", pct: 47 },
      ssh_hardening: { label: "Hardening SSH configuration...", pct: 49 },
      kernel_hardening: { label: "Applying kernel & performance tuning...", pct: 51 },
      swap: { label: "Configuring swap...", pct: 53 },
      firewall: { label: "Setting up UFW, fail2ban, auto-updates...", pct: 56 },
      docker: { label: "Installing Docker...", pct: 59 },
      hardening_done: { label: "Server hardening complete ✓", pct: 62, type: "success" },
      supabase: { label: "Setting up Supabase directory...", pct: 64 },
      supabase_env: { label: "Writing configs & hashing password...", pct: 67 },
      supabase_caddy: { label: "Configuring Caddy + Authelia...", pct: 72 },
      supabase_caddyfile: { label: "Writing Caddyfile...", pct: 75 },
      pulling: { label: "docker compose pull (downloading images)...", pct: 78 },
      starting_containers: { label: "docker compose up -d...", pct: 86 },
      supabase_done: { label: "Supabase is running ✓", pct: 90, type: "success" },
      s3_backup: { label: "Configuring S3 backup...", pct: 91 },
      backup_init: { label: "Initializing restic backup repository...", pct: 94 },
      backup_first: { label: "Running first backup...", pct: 95 },
      mcp_setup: { label: "Setting up MCP server (Claude integration)...", pct: 97 },
      complete: { label: "🎉 Deployment complete!", pct: 100, type: "success" },
      failed: { label: "Deployment failed on the server", pct: 0, type: "error" },
    };

    let lastPhase = "";
    let tries = 0;
    const MAX_TRIES = 400; // ~20 min at 3s intervals (CX23 docker pull can take 15+ min)

    while (tries < MAX_TRIES) {
      if (signal?.aborted) return "aborted";
      try {
        const labels = await this.getServerLabels(serverId);
        const phase = labels.deploy_phase || "";

        if (phase && phase !== lastPhase) {
          const info = PHASE_MAP[phase] || { label: `Phase: ${phase}`, pct: 50 };
          onStatus(info);
          lastPhase = phase;
          if (phase === "complete") return "complete";
          if (phase === "failed") return "failed";
        }
      } catch {
        // Silently retry — API hiccups during provisioning are normal
      }
      await new Promise((r) => setTimeout(r, 3000));
      tries++;
    }
    return "timeout";
  }

  async getAction(id) {
    const data = await this.request("GET", `/actions/${id}`);
    return data.action;
  }

  async waitForAction(actionId, onProgress) {
    let tries = 0;
    while (tries < 120) {
      const action = await this.getAction(actionId);
      if (onProgress) onProgress(action.progress);
      if (action.status === "success") return action;
      if (action.status === "error") throw new Error(`Action failed: ${action.error?.message}`);
      await new Promise((r) => setTimeout(r, 3000));
      tries++;
    }
    throw new Error("Timeout waiting for action");
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN COMPONENT
// ─────────────────────────────────────────────────────────────────────────────
export default function SupabaseDeployer() {
  const [step, setStep] = useState(0);
  const [logs, setLogs] = useState([]);
  const [status, setStatus] = useState("idle");
  const [progress, setProgress] = useState(0);
  const [expandedFaq, setExpandedFaq] = useState(null);
  const [tokenValid, setTokenValid] = useState(null);
  const [tokenChecking, setTokenChecking] = useState(false);
  const [deployError, setDeployError] = useState(null);
  const [showPassword, setShowPassword] = useState(false);
  const [copyFeedback, setCopyFeedback] = useState(false);
  const logsRef = useRef(null);
  const deployAbort = useRef(null);

  const [config, setConfig] = useState({
    hetznerCloudToken: "",
    serverName: "supabase-prod",
    deployUser: "deploy",
    location: "fsn1",
    serverType: "cx33",
    domain: "",
    supabaseUser: "",
    supabasePassword: "",
    supabaseEmail: "",
    displayName: "",
    enableAuthelia: true,
    enableRedis: true,
    s3Bucket: "",
    s3Region: "us-east-1",
    s3AccessKey: "",
    s3SecretKey: "",
    healthcheckUrl: "",
    smtpHost: "",
    smtpPort: "587",
    smtpUser: "",
    smtpPass: "",
    smtpSenderName: "",
    smtpAdminEmail: "",
    siteUrl: "",
    additionalRedirectUrls: "",
  });

  const [secrets, setSecrets] = useState(null);
  const [sshPrivateKey, setSshPrivateKey] = useState(null);
  const [serverIp, setServerIp] = useState(null);
  const [serverId, setServerId] = useState(null);

  const update = useCallback((k, v) => setConfig((p) => ({ ...p, [k]: v })), []);

  const log = useCallback((msg, type = "info") => {
    setLogs((p) => [...p, { msg, type, ts: new Date().toLocaleTimeString() }]);
  }, []);

  useEffect(() => {
    if (logsRef.current) logsRef.current.scrollTop = logsRef.current.scrollHeight;
  }, [logs]);

  // ── Validate API token ────────────────────────────────────────────────
  const validateToken = useCallback(async () => {
    if (config.hetznerCloudToken.length < 10) return;
    setTokenChecking(true);
    setTokenValid(null);
    try {
      const client = new HetznerClient(config.hetznerCloudToken);
      await client.validateToken();
      setTokenValid(true);
    } catch {
      setTokenValid(false);
    }
    setTokenChecking(false);
  }, [config.hetznerCloudToken]);

  // ── Deploy ────────────────────────────────────────────────────────────
  const deploy = useCallback(async () => {
    setStatus("running");
    setProgress(0);
    setLogs([]);
    setDeployError(null);

    const client = new HetznerClient(config.hetznerCloudToken);
    let _sshPrivateKey = null;
    let _serverIp = null;

    try {
      // 1. Generate secrets
      log("Generating cryptographic secrets (client-side)...");
      setProgress(3);
      const generatedSecrets = await generateAllSecrets();
      setSecrets(generatedSecrets);
      log("JWT secret, API keys, and encryption keys generated ✓", "success");

      // 2. Generate SSH keypair in browser and upload to Hetzner
      log("Generating ed25519 SSH keypair (client-side)...");
      setProgress(6);
      const sshKeypair = await generateSshKeypair(config.serverName);
      _sshPrivateKey = sshKeypair.privateKey;
      setSshPrivateKey(sshKeypair.privateKey);
      log("SSH keypair generated in browser ✓", "success");

      setProgress(8);
      const sshKeyName = `${config.serverName}-deploy-${Date.now()}`;
      log("Uploading public key to Hetzner...");
      const sshKey = await client.createSshKey(sshKeyName, sshKeypair.publicKey);
      log(`SSH key uploaded: ${sshKey.name} ✓`, "success");
      setProgress(12);

      // 3. Create firewall
      log("Creating firewall rules (22, 80, 443)...");
      const firewall = await client.createFirewall(`${config.serverName}-fw`);
      log(`Firewall created: ${firewall.name} ✓`, "success");
      setProgress(18);

      // 4. Generate cloud-init
      log("Building deployment script (cloud-init)...");
      const cloudInit = await generateCloudInit(config, generatedSecrets);
      setProgress(22);
      log("Cloud-init script generated ✓", "success");

      // 5. Create server
      log(`Provisioning ${config.serverType.toUpperCase()} in ${config.location}...`);
      setProgress(25);

      // Inject the server ID into cloud-init after creation
      // Cloud-init discovers its own ID via Hetzner metadata service (169.254.169.254)
      const { server, action } = await client.createServer({
        name: config.serverName,
        serverType: config.serverType,
        location: config.location,
        sshKeyIds: [sshKey.id],
        firewallIds: [firewall.id],
        userData: cloudInit,
      });
      setServerId(server.id);

      const ip = server.public_net?.ipv4?.ip;
      _serverIp = ip;
      setServerIp(ip);
      log(`Server created! ID: ${server.id}`, "success");
      if (ip) log(`Public IP: ${ip}`, "success");

      // Now update the cloud-init won't work retroactively, but the server
      // can discover its own ID via the Hetzner metadata service
      // Update cloud-init to use metadata endpoint instead
      // Actually — we update the server labels directly to inject the ID
      await client.updateServerLabels(server.id, {
        deploy_phase: "provisioning",
        managed_by: "supabase-deploy",
      });

      // 6. Wait for server to be ready
      log("Waiting for server to boot...");
      if (action) {
        await client.waitForAction(action.id, (p) => {
          setProgress(25 + Math.floor(p * 0.15));
        });
      }
      setProgress(40);
      log("Server is running ✓", "success");

      // 7. Poll deployment progress via server labels
      log("Server is executing the deployment script...");
      log("  Tracking progress via Hetzner server labels (zero-knowledge)");

      const pollResult = await client.pollDeployStatus(server.id, (info) => {
        log(info.label, info.type || "info");
        setProgress(info.pct);
      });

      if (pollResult === "failed") {
        throw new Error("Deployment failed on the server. SSH in and check /var/log/supabase-deploy.log");
      }

      // 8. Clean up: remove the API token from server labels
      try {
        await client.updateServerLabels(server.id, {
          deploy_phase: pollResult === "complete" ? "complete" : "unknown",
          managed_by: "supabase-deploy",
        });
      } catch { /* non-critical */ }

      // 9. Get final server IP
      const finalServer = await client.getServer(server.id);
      const finalIp = finalServer.public_net?.ipv4?.ip || ip;
      setServerIp(finalIp);

      log("", "info");
      if (pollResult === "timeout") {
        log("⏳ Status polling timed out — the server is still deploying in the background.", "warn");
        log("This is normal for smaller servers (CX23) where docker pull takes longer.", "info");
        log("Your credentials are ready below. The server will finish on its own.", "info");
        log(`SSH in to check progress:`, "info");
        log(`  ssh -i ~/.ssh/${config.serverName} ${config.deployUser}@${finalIp}`, "info");
        log(`  sudo cat /var/log/supabase-deploy.log`, "info");
        setProgress(95);
      } else {
        log(`🎉 Deployment complete! Supabase is live at ${config.domain}`, "success");
        log(`   Server IP: ${finalIp}`, "success");
        log(`   Point your DNS A record to this IP.`, "info");
        setProgress(100);
      }
      setStatus("success");

    } catch (err) {
      log(`\nError: ${err.message}`, "error");
      if (_serverIp) {
        log(`Server IP: ${_serverIp}`, "success");
        log(`Use the emergency panel above to copy your SSH key and access the server.`, "info");
      }
      setDeployError(err.message);
      setStatus("error");
    }
  }, [config, log]);

  // ── Validation ────────────────────────────────────────────────────────
  const canProceed = useMemo(() => {
    switch (step) {
      case 0: return true;
      case 1: return tokenValid === true;
      case 2: return (
        config.domain.length > 3 &&
        config.domain.startsWith("https://") &&
        config.deployUser.length > 0 &&
        /^[a-z_][a-z0-9_-]*$/.test(config.deployUser) &&
        config.supabaseUser.length > 0 &&
        config.supabasePassword.length >= 8 &&
        config.supabaseEmail.includes("@") &&
        config.displayName.length > 0 &&
        config.s3Bucket.length > 0 &&
        config.s3AccessKey.length > 0 &&
        config.s3SecretKey.length > 0
      );
      case 3: return true;
      case 4: return status === "success";
      default: return false;
    }
  }, [step, tokenValid, config, status]);

  const selectedServer = SERVER_TYPES.find((s) => s.id === config.serverType);

  // ── Copy all credentials ──────────────────────────────────────────────
  const copyCredentials = useCallback(() => {
    if (!secrets) return;
    const text = [
      `# Supabase Deployment — ${config.serverName}`,
      `# Generated: ${new Date().toISOString()}`,
      ``,
      `Dashboard: ${config.domain}`,
      `Server IP: ${serverIp}`,
      `Deploy User: ${config.deployUser}`,
      `SSH: ssh ${config.deployUser}@${serverIp}`,
      ``,
      `## Supabase Secrets`,
      `JWT_SECRET=${secrets.jwtSecret}`,
      `ANON_KEY=${secrets.anonKey}`,
      `SERVICE_ROLE_KEY=${secrets.serviceRoleKey}`,
      `POSTGRES_PASSWORD=${secrets.postgresPassword}`,
      ``,
      `## Backup`,
      `RESTIC_PASSWORD=${secrets.resticPassword}`,
      `S3_BUCKET=${config.s3Bucket}`,
      `S3_REGION=${config.s3Region}`,
      ``,
      `## SMTP`,
      `SMTP_HOST=${config.smtpHost || "(not configured)"}`,
      `SMTP_USER=${config.smtpUser}`,
      `SMTP_PASS=${config.smtpPass}`,
      ``,
      `## Authelia`,
      `Username: ${config.supabaseUser}`,
      `AUTHELIA_SESSION_SECRET=${secrets.autheliaSessionSecret}`,
      ``,
      `## Claude MCP Config (~/.claude/mcp.json)`,
      JSON.stringify({
        mcpServers: {
          [`supabase-${config.serverName}`]: {
            command: "ssh",
            args: [
              "-i", `~/.ssh/${config.serverName}`,
              "-o", "StrictHostKeyChecking=accept-new",
              `${config.deployUser}@${serverIp}`,
              `/home/${config.deployUser}/bin/supabase-mcp`
            ]
          }
        }
      }, null, 2),
      ``,
      `## SSH Private Key`,
      sshPrivateKey || "(not available)",
    ].join("\n");
    navigator.clipboard.writeText(text);
    setCopyFeedback(true);
    setTimeout(() => setCopyFeedback(false), 2000);
  }, [secrets, config, serverIp, sshPrivateKey]);

  // ─── RENDER ───────────────────────────────────────────────────────────
  return (
    <div style={S.root}>
      {/* Header */}
      <header style={S.header}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={S.logo}>S</div>
          <span style={{ fontSize: 14, fontWeight: 600, letterSpacing: "0.02em" }}>
            supabase<span style={{ color: C.green }}>:</span><span style={{ color: C.green }}>:</span>deploy
          </span>
        </div>
        <div style={S.badge}>
          <div style={{ width: 6, height: 6, borderRadius: "50%", background: C.green }} />
          zero-knowledge · open source
        </div>
      </header>

      {/* Progress */}
      <div style={S.container}>
        <div style={{ display: "flex", gap: 4, marginBottom: 28 }}>
          {STEPS.map((s, i) => (
            <div key={s.id} style={{ flex: 1 }}>
              <div style={{
                height: 3, borderRadius: 2, marginBottom: 6,
                background: i < step ? C.green : i === step ? `linear-gradient(90deg, ${C.green}, ${C.greenDark})` : C.border,
                transition: "all 0.4s",
              }} />
              <span style={{ fontSize: 10, color: i <= step ? C.muted : C.dim, textTransform: "uppercase", letterSpacing: "0.08em" }}>
                {s.label}
              </span>
            </div>
          ))}
        </div>

        <div style={{ minHeight: 420 }}>
          {/* ── STEP 0: WELCOME ────────────────────────────────── */}
          {step === 0 && (
            <FadeIn>
              <h1 style={S.title}>Deploy Supabase to Hetzner</h1>
              <p style={S.subtitle}>
                Production-ready, hardened, with 2FA and encrypted backups.
                <br />Everything runs in your browser — we never see your credentials.
              </p>

              <div style={{ display: "flex", flexDirection: "column", gap: 10, margin: "24px 0" }}>
                {[
                  ["🔐", "Zero Knowledge", "API keys exist only in browser memory (React state). Never stored, never transmitted to us."],
                  ["🛡️", "Hardened by Default", "SSH key-only, UFW, fail2ban, kernel sysctl, auto-updates, bcrypt-12, security headers."],
                  ["🔄", "Encrypted Backups", "Daily AES-256 encrypted backups via restic to AWS S3."],
                  ["⚡", "One Click, ~10 Min", "Server creation → OS hardening → Supabase + Caddy + Authelia + Redis → S3 backup cron."],
                ].map(([icon, title, desc]) => (
                  <Card key={title} style={{ display: "flex", gap: 14, padding: "14px 16px" }}>
                    <span style={{ fontSize: 20 }}>{icon}</span>
                    <div>
                      <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 2 }}>{title}</div>
                      <div style={{ fontSize: 12, color: C.muted, lineHeight: 1.5 }}>{desc}</div>
                    </div>
                  </Card>
                ))}
              </div>

              <Card style={{ background: "#0c1a14", borderColor: "#1a3a28", color: "#6ee7b7", fontSize: 12, lineHeight: 1.7, padding: "14px 16px" }}>
                <strong>Before you start:</strong> You need a Hetzner Cloud API token with Read & Write permissions.
                Get one at <strong>console.hetzner.cloud → Security → API Tokens</strong>.
                SSH keys are generated automatically in your browser — no need to create one yourself.
              </Card>

              {/* FAQ */}
              <div style={{ marginTop: 28 }}>
                <SectionLabel>FAQ</SectionLabel>
                {[
                  ["What does 'zero knowledge' mean?", "Your API tokens, passwords, and secrets exist only in your browser's JavaScript memory. They're never stored in localStorage, cookies, or sent to any server. When you close the tab, everything is gone. The deployment script is sent as cloud-init user-data directly to the Hetzner API."],
                  ["Can I verify this is safe?", "Yes — this tool is open source. You can read every line of code, check the Network tab to confirm API calls only go to api.hetzner.cloud, and audit the cloud-init script. No analytics, no tracking, no backend."],
                  ["What gets deployed?", "A hardened Ubuntu 24.04 server running: Supabase (Postgres, Auth, Storage, Realtime, Functions, Studio), Caddy reverse proxy with auto-HTTPS, Authelia 2FA, Redis session store, and restic encrypted daily backups."],
                  ["Can I deploy multiple instances?", "Yes — run this tool once per instance. Each gets its own server. All servers can back up to the same S3 bucket with isolated encryption keys."],
                  ["How do backups work?", "Encrypted daily backups via restic to your AWS S3 bucket. Each server gets its own prefix in the bucket. Restic handles deduplication, encryption, and retention automatically."],
                ].map(([q, a], i) => (
                  <Card key={i} style={{ marginBottom: 6, padding: 0, overflow: "hidden", cursor: "pointer" }}
                    onClick={() => setExpandedFaq(expandedFaq === i ? null : i)}>
                    <div style={{ padding: "11px 16px", display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 12, fontWeight: 500 }}>
                      {q}
                      <span style={{ color: C.dim, transform: expandedFaq === i ? "rotate(180deg)" : "none", transition: "transform 0.2s" }}>▾</span>
                    </div>
                    {expandedFaq === i && (
                      <div style={{ padding: "0 16px 12px", fontSize: 12, color: C.muted, lineHeight: 1.7 }}>{a}</div>
                    )}
                  </Card>
                ))}
              </div>
            </FadeIn>
          )}

          {/* ── STEP 1: API KEY ────────────────────────────────── */}
          {step === 1 && (
            <FadeIn>
              <h2 style={S.heading}>Hetzner API Token</h2>
              <p style={S.desc}>Your token is held in browser memory only. It calls the Hetzner API directly and is discarded when you close this tab.</p>

              <div style={{ marginBottom: 16 }}>
                <label style={S.label}>API Token</label>
                <div style={{ display: "flex", gap: 8 }}>
                  <input
                    type="password"
                    value={config.hetznerCloudToken}
                    onChange={(e) => { update("hetznerCloudToken", e.target.value); setTokenValid(null); }}
                    placeholder="Paste your Hetzner Cloud API token"
                    style={{ ...S.input, flex: 1, fontFamily: "'JetBrains Mono', monospace" }}
                    onFocus={(e) => (e.target.style.borderColor = C.green)}
                    onBlur={(e) => (e.target.style.borderColor = C.border)}
                  />
                  <button
                    onClick={validateToken}
                    disabled={tokenChecking || config.hetznerCloudToken.length < 10}
                    style={{
                      ...S.btn,
                      background: tokenChecking ? C.surface : C.greenDark,
                      color: tokenChecking ? C.muted : "#000",
                      opacity: config.hetznerCloudToken.length < 10 ? 0.4 : 1,
                      minWidth: 90,
                    }}
                  >
                    {tokenChecking ? "Checking..." : "Validate"}
                  </button>
                </div>
                {tokenValid === true && <div style={{ fontSize: 11, color: C.green, marginTop: 6 }}>✓ Token is valid — connected to Hetzner Cloud</div>}
                {tokenValid === false && <div style={{ fontSize: 11, color: "#ef4444", marginTop: 6 }}>✗ Invalid token. Check console.hetzner.cloud → Security → API Tokens (Read & Write)</div>}
                <div style={{ fontSize: 10, color: C.dim, marginTop: 4 }}>console.hetzner.cloud → Security → API Tokens → Generate (Read & Write)</div>
              </div>

              <Card style={{ fontSize: 12, color: C.muted, lineHeight: 1.7 }}>
                <strong style={{ color: C.text }}>How this works:</strong><br />
                • Your token calls api.hetzner.cloud directly from your browser<br />
                • It creates a server, uploads a cloud-init script, and configures a firewall<br />
                • The token never touches our servers — verify in your browser&apos;s Network tab<br />
                • The token is discarded from memory when you close this tab
              </Card>
            </FadeIn>
          )}

          {/* ── STEP 2: CONFIGURE ──────────────────────────────── */}
          {step === 2 && (
            <FadeIn>
              <h2 style={S.heading}>Configuration</h2>
              <p style={S.desc}>Choose your server, set up Supabase credentials, and configure backups.</p>

              <SectionLabel>Server</SectionLabel>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <Field label="Server Name" value={config.serverName} onChange={(v) => update("serverName", v)} placeholder="supabase-prod" />
                <Field label="Deploy User (SSH login)" value={config.deployUser} onChange={(v) => update("deployUser", v)} placeholder="deploy"
                  hint="Linux user created on the server. Root login is disabled."
                  error={config.deployUser.length > 0 && !/^[a-z_][a-z0-9_-]*$/.test(config.deployUser) ? "Lowercase letters, numbers, hyphens, underscores only" : null}
                />
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 16 }}>
                <div>
                  <label style={S.label}>Location</label>
                  <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                    {LOCATIONS.map((l) => (
                      <Opt key={l.id} selected={config.location === l.id} onClick={() => update("location", l.id)}>
                        <span>{l.flag}</span>
                        <span style={{ fontSize: 12, flex: 1 }}>{l.name}</span>
                        <span style={{ fontSize: 10, color: C.dim }}>{l.id}</span>
                      </Opt>
                    ))}
                  </div>
                </div>
                <div>
                  <label style={S.label}>Server Type</label>
                  <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                    {SERVER_TYPES.map((t) => (
                      <Opt key={t.id} selected={config.serverType === t.id} onClick={() => update("serverType", t.id)}>
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: 12, fontWeight: 600, display: "flex", alignItems: "center", gap: 6 }}>
                            {t.id.toUpperCase()}
                            {t.rec && <Badge>REC</Badge>}
                          </div>
                          <div style={{ fontSize: 10, color: C.dim }}>{t.cpu} · {t.ram} · {t.disk}</div>
                        </div>
                        <span style={{ fontSize: 11, color: C.muted }}>€{t.price}/mo</span>
                      </Opt>
                    ))}
                  </div>
                </div>
              </div>

              <SectionLabel>Supabase Credentials</SectionLabel>
              <Field label="Supabase API Domain (must start with https://)" value={config.domain} onChange={(v) => update("domain", v)}
                placeholder="https://supabase.yourdomain.com"
                hint="Point your DNS A record to the server IP after deployment"
                error={config.domain.length > 0 && !config.domain.startsWith("https://") ? "Must start with https://" : null}
              />
              <Field label="Frontend App URL (optional)" value={config.siteUrl} onChange={(v) => update("siteUrl", v)}
                placeholder="https://yourapp.com"
                hint="Where email confirmation links redirect to. Defaults to your Supabase domain if left blank."
              />
              <Field label="Additional Redirect URLs (optional)" value={config.additionalRedirectUrls} onChange={(v) => update("additionalRedirectUrls", v)}
                placeholder="https://yourapp.com,http://localhost:3000"
                hint="Comma-separated list of allowed redirect URLs for auth callbacks"
              />
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <Field label="Username" value={config.supabaseUser} onChange={(v) => update("supabaseUser", v)} placeholder="admin" />
                <div>
                  <label style={S.label}>Password</label>
                  <div style={{ position: "relative" }}>
                    <input type={showPassword ? "text" : "password"} value={config.supabasePassword}
                      onChange={(e) => update("supabasePassword", e.target.value)}
                      placeholder="Min 8 characters"
                      style={{ ...S.input, width: "100%", paddingRight: 36 }}
                      onFocus={(e) => (e.target.style.borderColor = C.green)}
                      onBlur={(e) => (e.target.style.borderColor = C.border)}
                    />
                    <span onClick={() => setShowPassword(!showPassword)}
                      style={{ position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)", cursor: "pointer", fontSize: 12, color: C.dim, userSelect: "none" }}>
                      {showPassword ? "Hide" : "Show"}
                    </span>
                  </div>
                  {config.supabasePassword.length > 0 && config.supabasePassword.length < 8 &&
                    <div style={{ fontSize: 10, color: "#ef4444", marginTop: 3 }}>Must be at least 8 characters</div>
                  }
                </div>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <Field label="Authelia Email" value={config.supabaseEmail} onChange={(v) => update("supabaseEmail", v)} placeholder="you@email.com" />
                <Field label="Display Name" value={config.displayName} onChange={(v) => update("displayName", v)} placeholder="Your Name" />
              </div>

              <SectionLabel>Options</SectionLabel>
              <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
                <Toggle
                  label="Authelia 2FA"
                  on={config.enableAuthelia}
                  set={(v) => {
                    update("enableAuthelia", v);
                    if (!v) update("enableRedis", false); // Auto-disable Redis when Authelia is off
                  }}
                />
                <Toggle
                  label="Redis Sessions"
                  on={config.enableRedis && config.enableAuthelia}
                  set={(v) => update("enableRedis", v)}
                  disabled={!config.enableAuthelia}
                />
              </div>
              {!config.enableAuthelia && (
                <div style={{ fontSize: 11, color: C.dim, marginTop: -8, marginBottom: 16 }}>
                  Redis is only used for Authelia sessions. Enable Authelia to use Redis.
                </div>
              )}

              <SectionLabel>AWS S3 (Backups)</SectionLabel>
              <Card style={{ background: "#0c1a14", borderColor: "#1a3a28", color: "#6ee7b7", fontSize: 12, lineHeight: 1.7, padding: "12px 16px", marginBottom: 14 }}>
                <strong>Encrypted backups to S3.</strong> Each deployment backs up to its own
                prefix (<code style={{ background: "#1a3a28", padding: "1px 5px", borderRadius: 3 }}>s3://your-bucket/{config.serverName || "server-name"}</code>).
                Reuse the same bucket for multiple servers — backups are isolated by server name with separate encryption keys.
                <div style={{ marginTop: 8, paddingTop: 8, borderTop: "1px solid #1a3a28", fontSize: 11, color: "#4ade80" }}>
                  <strong>Setup:</strong> Create an S3 bucket and an IAM user with <strong>s3:PutObject, s3:GetObject, s3:ListBucket, s3:DeleteObject</strong> permissions on the bucket.
                </div>
              </Card>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <Field label="S3 Bucket Name" value={config.s3Bucket} onChange={(v) => update("s3Bucket", v)} placeholder="my-supabase-backups" />
                <Field label="AWS Region" value={config.s3Region} onChange={(v) => update("s3Region", v)} placeholder="us-east-1" />
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <Field label="AWS Access Key ID" value={config.s3AccessKey} onChange={(v) => update("s3AccessKey", v)} placeholder="AKIA..." />
                <Field label="AWS Secret Access Key" type="password" value={config.s3SecretKey} onChange={(v) => update("s3SecretKey", v)} placeholder="Your secret key" />
              </div>
              <Field label="Health-check URL (optional)" value={config.healthcheckUrl} onChange={(v) => update("healthcheckUrl", v)}
                placeholder="https://hc-ping.com/your-uuid"
                hint="healthchecks.io, ntfy.sh, or similar — pinged after each backup"
              />

              <SectionLabel>SMTP (Transactional Email)</SectionLabel>
              <Card style={{ background: "#0c0f1a", borderColor: "#1a2040", color: "#93c5fd", fontSize: 12, lineHeight: 1.7, padding: "12px 16px", marginBottom: 14 }}>
                <strong>Required for auth emails</strong> — password resets, magic links, invite emails.
                Skip now and emails won&apos;t send (users auto-confirmed). Recommended: <strong>Resend</strong> (free 3k/mo) — use <code style={{ background: "#1a2040", padding: "1px 5px", borderRadius: 3 }}>smtp.resend.com</code> port 587, username <code style={{ background: "#1a2040", padding: "1px 5px", borderRadius: 3 }}>resend</code>, password = your API key.
              </Card>
              <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 12 }}>
                <Field label="SMTP Host" value={config.smtpHost} onChange={(v) => update("smtpHost", v)} placeholder="smtp.resend.com" />
                <Field label="SMTP Port" value={config.smtpPort} onChange={(v) => update("smtpPort", v)} placeholder="587" />
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <Field label="SMTP Username" value={config.smtpUser} onChange={(v) => update("smtpUser", v)} placeholder="resend" />
                <Field label="SMTP Password / API Key" type="password" value={config.smtpPass} onChange={(v) => update("smtpPass", v)} placeholder="re_..." />
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <Field label="Sender Name" value={config.smtpSenderName} onChange={(v) => update("smtpSenderName", v)} placeholder="My App" />
                <Field label="Admin Email" value={config.smtpAdminEmail} onChange={(v) => update("smtpAdminEmail", v)} placeholder="no-reply@yourdomain.com" />
              </div>
            </FadeIn>
          )}

          {/* ── STEP 3: REVIEW ─────────────────────────────────── */}
          {step === 3 && (
            <FadeIn>
              <h2 style={S.heading}>Review & Deploy</h2>
              <p style={S.desc}>Confirm everything looks right. Deployment takes ~10 minutes.</p>

              <Card style={{ padding: 0, overflow: "hidden", marginBottom: 14 }}>
                {[
                  ["Server", `${config.serverType.toUpperCase()} in ${LOCATIONS.find((l) => l.id === config.location)?.name} — €${selectedServer?.price}/mo`],
                  ["Domain", config.domain],
                  ["Proxy", "Caddy (auto-TLS via Let's Encrypt)"],
                  ["Auth", config.enableAuthelia ? `Authelia 2FA (user: ${config.supabaseUser})` : `Basic Auth (user: ${config.supabaseUser})`],
                  ["Redis", config.enableRedis ? "Enabled (session store)" : "Disabled"],
                  ["Backups", `Restic → S3 (${config.s3Bucket} in ${config.s3Region}), daily 3 AM, encrypted`],
                  ["SMTP", config.smtpHost ? `${config.smtpHost}:${config.smtpPort} (${config.smtpSenderName || config.smtpUser})` : "Not configured — email auto-confirm enabled"],
                  ["SSH Access", `User: ${config.deployUser} (root login disabled, key generated in browser)`],
                  ["Management", `${config.domain}/admin/ (protected by ${config.enableAuthelia ? 'Authelia' : 'Basic Auth'})`],
                  ["Hardening", "SSH hardening + UFW + fail2ban + sysctl + auto-updates + Docker security"],
                ].map(([k, v], i, arr) => (
                  <div key={k} style={{
                    display: "flex", justifyContent: "space-between", padding: "10px 16px",
                    fontSize: 12, borderBottom: i < arr.length - 1 ? `1px solid ${C.border}` : "none",
                  }}>
                    <span style={{ color: C.dim }}>{k}</span>
                    <span style={{ textAlign: "right", maxWidth: "60%" }}>{v}</span>
                  </div>
                ))}
              </Card>

              <div style={{
                display: "flex", justifyContent: "space-between", alignItems: "center",
                padding: "14px 16px", background: "#0c1a14", border: `1px solid #1a3a28`,
                borderRadius: 8, fontSize: 13, marginBottom: 14,
              }}>
                <span style={{ color: "#6ee7b7" }}>Estimated server cost</span>
                <span style={{ color: C.green, fontWeight: 700, fontSize: 16 }}>€{selectedServer?.price}/mo</span>
              </div>

              <Card style={{ background: "#1a1710", borderColor: "#3a3020", color: "#d4a044", fontSize: 12, lineHeight: 1.7, padding: "14px 16px" }}>
                <strong>⚠ DNS Reminder:</strong> After deployment, point an A record for{" "}
                <strong>{config.domain.replace(/^https?:\/\//, "")}</strong> to the server IP.
                Caddy will auto-provision the TLS certificate once DNS propagates.
              </Card>
            </FadeIn>
          )}

          {/* ── STEP 4: DEPLOY ─────────────────────────────────── */}
          {step === 4 && (
            <FadeIn>
              <h2 style={S.heading}>
                {status === "idle" ? "Ready to Deploy" :
                 status === "running" ? "Deploying..." :
                 status === "success" ? "Deployment Complete! 🎉" :
                 "Deployment Failed"}
              </h2>
              <p style={S.desc}>
                {status === "idle" && "This will create a real Hetzner server and deploy Supabase."}
                {status === "running" && "Do not close this tab. Your server is being provisioned."}
                {status === "success" && "Your Supabase instance is live. Save your credentials on the next page."}
                {status === "error" && "Something went wrong. Check the logs below."}
              </p>

              {status === "idle" && (
                <button onClick={deploy} style={S.deployBtn}
                  onMouseDown={(e) => (e.target.style.transform = "scale(0.98)")}
                  onMouseUp={(e) => (e.target.style.transform = "scale(1)")}>
                  🚀 Start Deployment
                </button>
              )}

              {status !== "idle" && (
                <>
                  {/* Emergency credentials — show ABOVE logs so user sees it immediately */}
                  {status === "error" && (sshPrivateKey || serverIp) && (
                    <div style={{
                      marginBottom: 14, border: "2px solid #ef4444", borderRadius: 10,
                      background: "linear-gradient(135deg, #1a0a0a, #0f0808)", overflow: "hidden",
                    }}>
                      <div style={{
                        padding: "12px 16px", background: "#ef4444", color: "#fff",
                        fontSize: 14, fontWeight: 700, textAlign: "center",
                      }}>
                        EMERGENCY ACCESS — Save these NOW
                      </div>
                      <div style={{ padding: "16px" }}>
                        {serverIp && (
                          <div style={{ marginBottom: 12, fontSize: 13, color: C.text }}>
                            <div style={{ marginBottom: 6 }}>Server IP: <strong>{serverIp}</strong></div>
                            <div style={{
                              background: "#0a0a0c", padding: "8px 12px", borderRadius: 6,
                              fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: C.green,
                            }}>
                              ssh -i ~/.ssh/{config.serverName} {config.deployUser}@{serverIp}
                            </div>
                          </div>
                        )}
                        {sshPrivateKey && (
                          <div>
                            <button onClick={() => {
                              navigator.clipboard.writeText(sshPrivateKey).then(() => {
                                setCopyFeedback(true);
                                setTimeout(() => setCopyFeedback(false), 3000);
                              });
                            }} style={{
                              width: "100%", padding: "12px", border: "none", borderRadius: 8, cursor: "pointer",
                              fontSize: 14, fontWeight: 700, marginBottom: 10,
                              background: copyFeedback ? C.green : "#ef4444",
                              color: copyFeedback ? "#000" : "#fff",
                            }}>
                              {copyFeedback ? "SSH KEY COPIED TO CLIPBOARD ✓" : "COPY SSH PRIVATE KEY"}
                            </button>
                            <div style={{ fontSize: 11, color: C.dim, lineHeight: 1.6 }}>
                              1. Click the button above to copy the key<br />
                              2. Save to file: <code style={{ background: C.surfaceAlt, padding: "1px 4px", borderRadius: 3 }}>pbpaste &gt; ~/.ssh/{config.serverName} && chmod 600 ~/.ssh/{config.serverName}</code><br />
                              3. SSH in: <code style={{ background: C.surfaceAlt, padding: "1px 4px", borderRadius: 3 }}>ssh -i ~/.ssh/{config.serverName} {config.deployUser}@{serverIp}</code><br />
                              4. Check logs: <code style={{ background: C.surfaceAlt, padding: "1px 4px", borderRadius: 3 }}>sudo cat /var/log/supabase-deploy.log</code>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  <div style={{ height: 6, background: C.border, borderRadius: 3, marginBottom: 14, overflow: "hidden" }}>
                    <div style={{
                      height: "100%", borderRadius: 3, width: `${progress}%`,
                      background: status === "error" ? "#ef4444" : `linear-gradient(90deg, ${C.green}, ${C.greenDark})`,
                      transition: "width 0.5s ease",
                    }} />
                  </div>
                  <div style={{ fontSize: 11, color: C.dim, textAlign: "right", marginBottom: 8 }}>{progress}%</div>

                  <div ref={logsRef} style={S.logWindow}>
                    {logs.map((l, i) => (
                      <div key={i} style={{
                        padding: "2px 14px", fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
                        color: l.type === "error" ? "#ef4444" : l.type === "success" ? C.green : l.msg.startsWith("  →") ? C.dim : C.muted,
                      }}>
                        <span style={{ color: "#2a2a30", marginRight: 8 }}>{l.ts}</span>{l.msg}
                      </div>
                    ))}
                  </div>

                  {status === "error" && (
                    <button onClick={() => { setStatus("idle"); setProgress(0); setLogs([]); }}
                      style={{ ...S.btn, marginTop: 12, background: "#1a1a1f", color: C.text }}>
                      ↻ Retry
                    </button>
                  )}
                </>
              )}
            </FadeIn>
          )}

          {/* ── STEP 5: COMPLETE ───────────────────────────────── */}
          {step === 5 && (
            <FadeIn>
              <h2 style={S.heading}>🎉 You&apos;re Live!</h2>
              <p style={S.desc}>
                Save these credentials now — they only exist in your browser and vanish when you close this tab.
              </p>

              <Card style={{ padding: 0, overflow: "hidden", marginBottom: 14 }}>
                <div style={{
                  padding: "10px 16px", background: C.surfaceAlt, borderBottom: `1px solid ${C.border}`,
                  fontSize: 12, fontWeight: 600, color: C.muted, display: "flex", justifyContent: "space-between",
                }}>
                  <span>Credentials</span>
                  <button onClick={copyCredentials} style={{
                    ...S.btn, padding: "2px 10px", fontSize: 10,
                    background: copyFeedback ? C.greenDark : C.surface,
                    color: copyFeedback ? "#000" : C.muted,
                  }}>
                    {copyFeedback ? "Copied ✓" : "Copy All"}
                  </button>
                </div>
                {[
                  ["Dashboard", config.domain],
                  ["Server IP", serverIp || "Assigning..."],
                  ["SSH", `ssh ${config.deployUser}@${serverIp}`],
                  ["Deploy User", config.deployUser],
                  ["Username", config.supabaseUser],
                  ["JWT Secret", secrets?.jwtSecret],
                  ["Anon Key", secrets?.anonKey],
                  ["Service Role Key", secrets?.serviceRoleKey],
                  ["Postgres Password", secrets?.postgresPassword],
                  ["Restic Backup Password", secrets?.resticPassword],
                  ["S3 Backup Bucket", `${config.s3Bucket} (${config.s3Region})`],
                  ...(config.enableAuthelia ? [["2FA Secret (TOTP)", secrets?.totpSecret]] : []),
                ].map(([k, v], i, arr) => (
                  <div key={k} style={{
                    display: "flex", justifyContent: "space-between", alignItems: "center",
                    padding: "8px 16px", fontSize: 11, borderBottom: i < arr.length - 1 ? `1px solid ${C.surfaceAlt}` : "none",
                  }}>
                    <span style={{ color: C.dim, minWidth: 130 }}>{k}</span>
                    <code style={{
                      color: C.text, fontSize: 10, background: C.bg, padding: "2px 6px",
                      borderRadius: 3, maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                    }}>{v}</code>
                  </div>
                ))}
              </Card>

              {sshPrivateKey && (
                <Card style={{ padding: 0, overflow: "hidden", marginBottom: 14 }}>
                  <div style={{
                    padding: "10px 16px", background: C.surfaceAlt, borderBottom: `1px solid ${C.border}`,
                    fontSize: 12, fontWeight: 600, color: C.muted, display: "flex", justifyContent: "space-between",
                  }}>
                    <span>SSH Private Key</span>
                    <button onClick={() => {
                      navigator.clipboard.writeText(sshPrivateKey);
                      setCopyFeedback(true); setTimeout(() => setCopyFeedback(false), 2000);
                    }} style={{
                      ...S.btn, padding: "2px 10px", fontSize: 10, background: C.surface, color: C.muted,
                    }}>Copy Key</button>
                  </div>
                  <pre style={{
                    padding: "10px 16px", margin: 0, fontSize: 10, color: C.muted,
                    whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 180, overflowY: "auto",
                    fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.5,
                  }}>{sshPrivateKey}</pre>
                  <div style={{ padding: "8px 16px", fontSize: 11, color: "#d4a044", borderTop: `1px solid ${C.border}` }}>
                    Save as <code style={{ background: C.surfaceAlt, padding: "1px 5px", borderRadius: 3 }}>~/.ssh/{config.serverName}</code> and run: <code style={{ background: C.surfaceAlt, padding: "1px 5px", borderRadius: 3 }}>chmod 600 ~/.ssh/{config.serverName}</code>
                  </div>
                </Card>
              )}

              <Card style={{ background: "#1a0c0c", borderColor: "#3a1a1a", color: "#fca5a5", fontSize: 12, lineHeight: 1.7, padding: "14px 16px" }}>
                <strong>⚠ Save these credentials NOW!</strong> They exist only in browser memory.
                Once you close this tab, they are gone forever. Use a password manager.
              </Card>

              <Card style={{ background: "#1a1710", borderColor: "#3a3020", color: "#d4a044", fontSize: 12, lineHeight: 1.7, padding: "14px 16px", marginBottom: 14 }}>
                <strong>Using Cloudflare?</strong> Set SSL mode to <strong>Full</strong> (not Full Strict) in
                Cloudflare dashboard → SSL/TLS. Or use <strong>DNS-only mode</strong> (grey cloud icon)
                so Caddy can get its own Let&apos;s Encrypt certificate directly.
              </Card>

              <SectionLabel>Claude MCP Integration</SectionLabel>
              <Card style={{ padding: 0, overflow: "hidden", marginBottom: 14 }}>
                <div style={{
                  padding: "10px 16px", background: C.surfaceAlt, borderBottom: `1px solid ${C.border}`,
                  fontSize: 12, fontWeight: 600, color: C.muted, display: "flex", justifyContent: "space-between",
                }}>
                  <span>Add to ~/.claude/mcp.json (or Cursor / Windsurf)</span>
                  <button onClick={() => {
                    const mcpJson = JSON.stringify({
                      mcpServers: {
                        [`supabase-${config.serverName}`]: {
                          command: "ssh",
                          args: [
                            "-i", `~/.ssh/${config.serverName}`,
                            "-o", "StrictHostKeyChecking=accept-new",
                            `${config.deployUser}@${serverIp || "SERVER_IP"}`,
                            `/home/${config.deployUser}/bin/supabase-mcp`
                          ]
                        }
                      }
                    }, null, 2);
                    navigator.clipboard.writeText(mcpJson);
                    setCopyFeedback(true); setTimeout(() => setCopyFeedback(false), 2000);
                  }} style={{
                    ...S.btn, padding: "2px 10px", fontSize: 10,
                    background: copyFeedback ? C.greenDark : C.surface,
                    color: copyFeedback ? "#000" : C.muted,
                  }}>
                    {copyFeedback ? "Copied ✓" : "Copy JSON"}
                  </button>
                </div>
                <pre style={{
                  padding: "12px 16px", margin: 0, fontSize: 10, color: "#93c5fd",
                  whiteSpace: "pre-wrap", wordBreak: "break-all",
                  fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.6,
                }}>{JSON.stringify({
                  mcpServers: {
                    [`supabase-${config.serverName}`]: {
                      command: "ssh",
                      args: [
                        "-i", `~/.ssh/${config.serverName}`,
                        "-o", "StrictHostKeyChecking=accept-new",
                        `${config.deployUser}@${serverIp || "SERVER_IP"}`,
                        `/home/${config.deployUser}/bin/supabase-mcp`
                      ]
                    }
                  }
                }, null, 2)}</pre>
                <div style={{ padding: "8px 16px", fontSize: 11, color: C.dim, borderTop: `1px solid ${C.border}` }}>
                  37 tools: database, auth, storage, edge functions, migrations, RLS, realtime, logs &amp; admin
                </div>
              </Card>

              <SectionLabel>Next Steps</SectionLabel>
              <div style={{ fontSize: 12, color: C.muted, lineHeight: 2, paddingLeft: 4 }}>
                1. Save the SSH private key above to <strong style={{ color: C.text }}>~/.ssh/{config.serverName}</strong><br />
                2. Point DNS A record: <strong style={{ color: C.text }}>{config.domain.replace(/^https?:\/\//, "")}</strong> → <strong style={{ color: C.text }}>{serverIp}</strong><br />
                3. Wait 2–5 min for Caddy to get the TLS certificate<br />
                4. Visit <strong style={{ color: C.green }}>{config.domain}</strong> and log in<br />
                5. SSH: <code style={{ background: C.surfaceAlt, padding: "1px 5px", borderRadius: 3 }}>ssh -i ~/.ssh/{config.serverName} {config.deployUser}@{serverIp}</code><br />
                6. Management panel: <strong style={{ color: C.green }}>{config.domain}/admin/</strong><br />
                7. Backups run automatically to S3 (daily 3 AM)<br />
                8. Copy the MCP config above into <code style={{ background: C.surfaceAlt, padding: "1px 5px", borderRadius: 3 }}>~/.claude/mcp.json</code> to connect Claude
              </div>
              {config.enableAuthelia && (
                <Card style={{ background: "#0c1219", borderColor: "#1a2f4a", color: "#93c5fd", fontSize: 12, lineHeight: 1.8, padding: "14px 16px", marginTop: 14 }}>
                  <strong>Authenticator App Setup (2FA)</strong><br />
                  Copy the <strong>2FA Secret (TOTP)</strong> above and add it to Google Authenticator, Authy, or 1Password as a manual entry. That&apos;s it — no email, no portal, no SSH needed.
                </Card>
              )}
            </FadeIn>
          )}
        </div>

        {/* ── Navigation ────────────────────────────────────── */}
        <div style={{ display: "flex", justifyContent: "space-between", padding: "24px 0 40px", borderTop: `1px solid ${C.border}`, marginTop: 20 }}>
          {step > 0 && step < 5 && status !== "running" ? (
            <button onClick={() => setStep(step - 1)} style={S.navBtn}>← Back</button>
          ) : <div />}
          {step < 5 && (
            <button onClick={() => { if (step === 3) { setStep(4); } else setStep(step + 1); }}
              disabled={!canProceed || status === "running"}
              style={{
                ...S.navBtn, fontWeight: 700,
                background: canProceed && status !== "running" ? `linear-gradient(135deg, ${C.green}, ${C.greenDark})` : C.border,
                color: canProceed && status !== "running" ? "#000" : C.dim,
                cursor: canProceed && status !== "running" ? "pointer" : "not-allowed",
                border: "none",
              }}>
              {step === 3 ? "Begin Deployment →" : step === 4 ? "View Credentials →" : "Continue →"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Design Tokens ──────────────────────────────────────────────────────────
const C = {
  bg: "#0a0a0b",
  surface: "#111114",
  surfaceAlt: "#161619",
  border: "#1e1e23",
  text: "#e4e4e7",
  muted: "#a1a1aa",
  dim: "#52525b",
  green: "#3ecf8e",
  greenDark: "#1a9f60",
};

const S = {
  root: { minHeight: "100vh", background: C.bg, color: C.text, fontFamily: "'JetBrains Mono', 'SF Mono', 'Fira Code', monospace" },
  header: {
    borderBottom: `1px solid ${C.border}`, padding: "14px 24px",
    display: "flex", alignItems: "center", justifyContent: "space-between",
    background: `linear-gradient(180deg, #0f0f12, ${C.bg})`,
  },
  logo: {
    width: 30, height: 30, borderRadius: 7,
    background: `linear-gradient(135deg, ${C.green}, ${C.greenDark})`,
    display: "flex", alignItems: "center", justifyContent: "center",
    fontSize: 15, fontWeight: 800, color: "#000", fontFamily: "'JetBrains Mono', monospace",
  },
  badge: {
    display: "flex", alignItems: "center", gap: 6,
    background: C.surface, border: `1px solid ${C.border}`,
    borderRadius: 6, padding: "4px 10px", fontSize: 11, color: C.dim,
  },
  container: { maxWidth: 780, margin: "0 auto", padding: "20px 24px 0" },
  title: {
    fontSize: 26, fontWeight: 700, margin: "0 0 6px", lineHeight: 1.3,
    background: `linear-gradient(135deg, ${C.text} 30%, ${C.green})`,
    WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
  },
  subtitle: { color: C.dim, fontSize: 13, margin: "0 0 4px", lineHeight: 1.7 },
  heading: { fontSize: 20, fontWeight: 700, margin: "0 0 4px" },
  desc: { color: C.dim, fontSize: 12, margin: "0 0 20px", lineHeight: 1.6 },
  label: { display: "block", fontSize: 11, fontWeight: 600, color: C.muted, marginBottom: 5, letterSpacing: "0.03em" },
  input: {
    padding: "9px 12px", background: C.surface, border: `1px solid ${C.border}`,
    borderRadius: 6, color: C.text, fontSize: 12, outline: "none", boxSizing: "border-box",
    transition: "border-color 0.15s",
  },
  btn: {
    padding: "9px 16px", border: `1px solid ${C.border}`, borderRadius: 6,
    fontSize: 12, fontFamily: "inherit", cursor: "pointer", transition: "all 0.15s",
  },
  navBtn: {
    padding: "10px 20px", border: `1px solid ${C.border}`, borderRadius: 8,
    background: C.surface, color: C.text, fontSize: 12, fontFamily: "inherit",
    cursor: "pointer", transition: "all 0.15s",
  },
  deployBtn: {
    width: "100%", padding: "14px", border: "none", borderRadius: 8,
    fontSize: 14, fontWeight: 700, fontFamily: "inherit", cursor: "pointer",
    background: `linear-gradient(135deg, ${C.green}, ${C.greenDark})`,
    color: "#000", marginBottom: 16, transition: "transform 0.1s",
  },
  logWindow: {
    background: "#050506", border: `1px solid ${C.border}`, borderRadius: 8,
    padding: "10px 0", maxHeight: 300, overflowY: "auto",
  },
};

// ─── Micro-components ───────────────────────────────────────────────────────
function FadeIn({ children }) {
  return <div style={{ animation: "fadeIn 0.3s ease" }}>{children}
    <style>{`@keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }`}</style>
  </div>;
}

function Card({ children, style = {}, onClick }) {
  return <div onClick={onClick} style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: "12px 16px", ...style }}>{children}</div>;
}

function SectionLabel({ children }) {
  return <div style={{ fontSize: 10, fontWeight: 700, color: C.dim, textTransform: "uppercase", letterSpacing: "0.1em", margin: "20px 0 8px", borderBottom: `1px solid ${C.border}`, paddingBottom: 5 }}>{children}</div>;
}

function Badge({ children }) {
  return <span style={{ fontSize: 9, background: "#1a3a28", color: C.green, padding: "1px 5px", borderRadius: 3, fontWeight: 600 }}>{children}</span>;
}

function Opt({ children, selected, onClick, style = {} }) {
  return <div onClick={onClick} style={{
    display: "flex", alignItems: "center", gap: 8, padding: "8px 12px", borderRadius: 6,
    cursor: "pointer", background: selected ? "#0c1a14" : C.surface,
    border: `1px solid ${selected ? "#1a3a28" : C.border}`, transition: "all 0.15s", ...style,
  }}>{children}</div>;
}

function Toggle({ label, on, set, disabled }) {
  return (
    <div onClick={() => !disabled && set(!on)} style={{
      flex: 1, display: "flex", alignItems: "center", justifyContent: "space-between",
      padding: "10px 14px", background: C.surface, border: `1px solid ${C.border}`,
      borderRadius: 8, cursor: disabled ? "not-allowed" : "pointer",
      opacity: disabled ? 0.5 : 1,
    }}>
      <span style={{ fontSize: 12 }}>{label}</span>
      <div style={{ width: 36, height: 20, borderRadius: 10, background: on ? C.greenDark : "#2a2a30", position: "relative", transition: "background 0.2s" }}>
        <div style={{ width: 16, height: 16, borderRadius: "50%", background: "#fff", position: "absolute", top: 2, left: on ? 18 : 2, transition: "left 0.2s" }} />
      </div>
    </div>
  );
}

function Field({ label, value, onChange, placeholder, hint, error, type = "text" }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <label style={S.label}>{label}</label>
      <input type={type} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder}
        style={{ ...S.input, width: "100%" }}
        onFocus={(e) => (e.target.style.borderColor = C.green)}
        onBlur={(e) => (e.target.style.borderColor = C.border)}
      />
      {error && <div style={{ fontSize: 10, color: "#ef4444", marginTop: 3 }}>{error}</div>}
      {hint && !error && <div style={{ fontSize: 10, color: C.dim, marginTop: 3 }}>{hint}</div>}
    </div>
  );
}
