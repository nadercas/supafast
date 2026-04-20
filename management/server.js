const http = require('http');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

const PORT = process.env.PORT || 3001;
const SUPABASE_DIR = process.env.SUPABASE_DIR || '/opt/supabase';
const SERVER_NAME = process.env.SERVER_NAME || 'Supabase Server';
const DOCKER_HOST = process.env.DOCKER_HOST || 'tcp://localhost:2375';
const HOST_LOGS = '/host-logs';
const HOST_BACKUPS = '/host-backups';
const UPGRADE_DIR = path.join(SUPABASE_DIR, 'upgrade');
const PROXY_SECRET = process.env.PROXY_SECRET || '';
const AUDIT_LOG_PATH = path.join(UPGRADE_DIR, 'audit.log');

// Simple in-memory sliding-window rate limiter.
// Keyed by authenticated user (Remote-User) falling back to IP.
// Read limit sized for UI polling: dashboard refreshes every 5s with 3
// parallel calls (≈36/min) and upgrade polling is 20/min — 600/min gives
// ample headroom while still blocking scraping.
const rateBuckets = new Map();
function rateLimit(req, method) {
  const key = (req.headers['remote-user'] || req.socket.remoteAddress || 'anon').toLowerCase();
  const now = Date.now();
  const isMutate = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method);
  const limit = isMutate ? 30 : 600;
  const windowMs = 60_000;
  const bucketKey = key + '|' + (isMutate ? 'm' : 'r');
  const bucket = rateBuckets.get(bucketKey) || [];
  const fresh = bucket.filter((t) => now - t < windowMs);
  if (fresh.length >= limit) return false;
  fresh.push(now);
  rateBuckets.set(bucketKey, fresh);
  // Opportunistic cleanup so the map doesn't grow unbounded.
  if (rateBuckets.size > 1000) {
    for (const [k, v] of rateBuckets) {
      if (v.length === 0 || now - v[v.length - 1] > windowMs) rateBuckets.delete(k);
    }
  }
  return true;
}

function audit(req, action, target, result, extra) {
  try {
    const entry = {
      ts: new Date().toISOString(),
      user: req.headers['remote-user'] || 'unknown',
      ip: req.socket.remoteAddress || '',
      action,
      target: target || '',
      result: result || 'ok',
      ...(extra || {}),
    };
    fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify(entry) + '\n');
  } catch {}
}

const UPGRADABLE_SERVICES = new Set([
  'studio', 'kong', 'auth', 'rest', 'realtime', 'storage',
  'imgproxy', 'meta', 'functions', 'analytics', 'vector', 'supavisor',
]);

const SERVICE_TO_REPO = {
  studio: 'supabase/studio',
  kong: 'kong/kong',
  auth: 'supabase/gotrue',
  rest: 'postgrest/postgrest',
  realtime: 'supabase/realtime',
  storage: 'supabase/storage-api',
  imgproxy: 'darthsim/imgproxy',
  meta: 'supabase/postgres-meta',
  functions: 'supabase/edge-runtime',
  analytics: 'supabase/logflare',
  vector: 'timberio/vector',
  supavisor: 'supabase/supavisor',
};

const TAG_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$/;
// Floating/rolling tags we refuse to pin — they point at moving targets and
// break the "you know what version you're running" guarantee. Matches the
// rolling name alone ("latest", "main") or followed by arch/os suffixes
// ("latest_arm64", "main-ubuntu"). Does NOT match versioned pre-releases
// like "v2.189.0-rc.15" which embed the word mid-string after a real version.
const ROLLING_TAG_RE = /^(latest|main|master|dev|edge|stable|nightly|canary|unstable)([-_][A-Za-z0-9]+)*$/i;
function isPinnableTag(name) {
  return TAG_RE.test(name) && !ROLLING_TAG_RE.test(name);
}

// --- Input Validation ---

function isValidContainerId(id) {
  return /^[a-f0-9]{12,64}$/i.test(id);
}

function isValidServiceName(name) {
  return /^[a-z0-9_.-]+$/.test(name) && name.length < 128;
}

function sanitizeLines(n) {
  const num = parseInt(n, 10);
  return Number.isFinite(num) && num > 0 && num <= 5000 ? num : 100;
}

// --- MIME Types ---

const MIME = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

// --- Docker Socket Communication ---

function parseDockerHost() {
  const m = DOCKER_HOST.match(/^tcp:\/\/([^:]+):(\d+)$/);
  if (m) return { hostname: m[1], port: parseInt(m[2], 10) };
  return { hostname: 'localhost', port: 2375 };
}

const dockerConn = parseDockerHost();

function dockerRequest(method, reqPath, body) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: dockerConn.hostname,
      port: dockerConn.port,
      path: reqPath,
      method,
      headers: { 'Content-Type': 'application/json' },
    };
    const req = http.request(opts, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: data ? JSON.parse(data) : null });
        } catch {
          resolve({ status: res.statusCode, data: data });
        }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

function dockerRequestRaw(method, reqPath) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: dockerConn.hostname,
      port: dockerConn.port,
      path: reqPath,
      method,
    };
    const req = http.request(opts, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => resolve({ status: res.statusCode, data }));
    });
    req.on('error', reject);
    req.end();
  });
}

// --- Shell Exec Helper ---

function execAsync(cmd, opts = {}) {
  return new Promise((resolve, reject) => {
    exec(cmd, { timeout: 120000, ...opts }, (err, stdout, stderr) => {
      if (err) return reject(err);
      resolve({ stdout: stdout.toString(), stderr: stderr.toString() });
    });
  });
}

// --- /proc Readers ---

function readProc(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return '';
  }
}

function readFile(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return '';
  }
}

// --- CPU State (for delta calculation) ---

let prevCpu = null;

function getCpuUsage() {
  const stat = readProc('/proc/stat');
  const line = stat.split('\n').find((l) => l.startsWith('cpu '));
  if (!line) return { percent: 0 };
  const parts = line.trim().split(/\s+/).slice(1).map(Number);
  const idle = parts[3] + (parts[4] || 0);
  const total = parts.reduce((a, b) => a + b, 0);

  let percent = 0;
  if (prevCpu) {
    const dTotal = total - prevCpu.total;
    const dIdle = idle - prevCpu.idle;
    percent = dTotal > 0 ? Math.round(((dTotal - dIdle) / dTotal) * 100) : 0;
  }
  prevCpu = { total, idle };
  return { percent };
}

function getMemInfo() {
  const raw = readProc('/proc/meminfo');
  const map = {};
  raw.split('\n').forEach((line) => {
    const m = line.match(/^(\w+):\s+(\d+)/);
    if (m) map[m[1]] = parseInt(m[2], 10);
  });
  const totalMem = map.MemTotal || 0;
  const availMem = map.MemAvailable || map.MemFree || 0;
  const usedMem = totalMem - availMem;
  const totalSwap = map.SwapTotal || 0;
  const freeSwap = map.SwapFree || 0;
  const usedSwap = totalSwap - freeSwap;
  return {
    ram: {
      total: totalMem,
      used: usedMem,
      percent: totalMem > 0 ? Math.round((usedMem / totalMem) * 100) : 0,
    },
    swap: {
      total: totalSwap,
      used: usedSwap,
      percent: totalSwap > 0 ? Math.round((usedSwap / totalSwap) * 100) : 0,
    },
  };
}

function getDisk() {
  try {
    const { stdout } = require('child_process').execSync
      ? { stdout: require('child_process').execSync('df -B1 / 2>/dev/null || df -k /', { encoding: 'utf8' }) }
      : { stdout: '' };
    const lines = stdout.trim().split('\n');
    if (lines.length < 2) return { total: 0, used: 0, percent: 0 };
    const parts = lines[1].trim().split(/\s+/);
    const total = parseInt(parts[1], 10);
    const used = parseInt(parts[2], 10);
    const percent = parseInt(parts[4], 10) || (total > 0 ? Math.round((used / total) * 100) : 0);
    return { total, used, percent };
  } catch {
    return { total: 0, used: 0, percent: 0 };
  }
}

// --- Secrets Helpers ---

const SECRETS_ENV_PATH = path.join(SUPABASE_DIR, 'volumes', 'functions', '.env');

function parseEnvFile(content) {
  const env = new Map();
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) continue;
    const key = trimmed.slice(0, eqIndex).trim();
    let value = trimmed.slice(eqIndex + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    env.set(key, value);
  }
  return env;
}

function serializeEnvFile(env) {
  const lines = [];
  for (const [key, value] of env) {
    if (/[\s#"'\\$]/.test(value)) {
      lines.push(`${key}="${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`);
    } else {
      lines.push(`${key}=${value}`);
    }
  }
  return lines.join('\n') + '\n';
}

async function restartEdgeFunctionsContainer() {
  try {
    const result = await dockerRequest('GET', '/containers/json?all=true&filters=' + encodeURIComponent(JSON.stringify({ name: ['supabase-edge-functions'] })));
    const containers = result.data || [];
    if (containers.length === 0) return { restarted: false, error: 'Container not found' };
    const containerId = containers[0].Id;
    const restart = await dockerRequest('POST', `/containers/${containerId}/restart?t=10`);
    return { restarted: restart.status === 204 };
  } catch (err) {
    return { restarted: false, error: err.message };
  }
}

async function handleGetSecrets(req, res) {
  try {
    if (!fs.existsSync(SECRETS_ENV_PATH)) {
      return sendJson(res, { keys: [] });
    }
    const env = parseEnvFile(fs.readFileSync(SECRETS_ENV_PATH, 'utf8'));
    const keys = Array.from(env.keys());
    sendJson(res, { keys });
  } catch (err) {
    sendJson(res, { error: 'Failed to read secrets', details: err.message }, 500);
  }
}

async function handleSetSecret(req, res) {
  const body = await readBody(req);
  const { key, value } = body;

  if (!key || typeof key !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
    return sendJson(res, { error: 'Invalid key name. Use letters, numbers, and underscores only.' }, 400);
  }
  if (value === undefined || value === null || typeof value !== 'string') {
    return sendJson(res, { error: 'Value is required and must be a string' }, 400);
  }

  try {
    let env = new Map();
    if (fs.existsSync(SECRETS_ENV_PATH)) {
      env = parseEnvFile(fs.readFileSync(SECRETS_ENV_PATH, 'utf8'));
    }
    const existed = env.has(key);
    env.set(key, value);
    fs.writeFileSync(SECRETS_ENV_PATH, serializeEnvFile(env), 'utf8');
    audit(req, existed ? 'secret.update' : 'secret.create', key, 'ok');
    // The systemd path unit (supabase-functions-reload.path) detects the file
    // change and runs `docker compose up --force-recreate functions` on the host,
    // which re-reads env_file so the new secret is live in ~5 seconds.
    sendJson(res, { success: true, action: existed ? 'updated' : 'created', key, restarted: true });
  } catch (err) {
    sendJson(res, { error: 'Failed to set secret', details: err.message }, 500);
  }
}

async function handleDeleteSecret(req, res, key) {
  if (!key || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
    return sendJson(res, { error: 'Invalid key name' }, 400);
  }

  try {
    if (!fs.existsSync(SECRETS_ENV_PATH)) {
      return sendJson(res, { error: 'No secrets file exists' }, 404);
    }
    const env = parseEnvFile(fs.readFileSync(SECRETS_ENV_PATH, 'utf8'));
    if (!env.has(key)) {
      return sendJson(res, { error: `Secret '${key}' not found` }, 404);
    }
    env.delete(key);
    fs.writeFileSync(SECRETS_ENV_PATH, serializeEnvFile(env), 'utf8');
    audit(req, 'secret.delete', key, 'ok');
    sendJson(res, { success: true, key, restarted: true });
  } catch (err) {
    sendJson(res, { error: 'Failed to delete secret', details: err.message }, 500);
  }
}

// --- API Handlers ---

async function handleSystem(req, res) {
  const hostname = readProc('/proc/sys/kernel/hostname').trim() || require('os').hostname();
  const uptimeSec = parseFloat(readProc('/proc/uptime').split(' ')[0]) || 0;
  const osRelease = readFile('/etc/os-release');
  const prettyName = (osRelease.match(/PRETTY_NAME="?([^"\n]+)"?/) || [])[1] || 'Unknown';

  let ip = '';
  try {
    const nets = require('os').networkInterfaces();
    for (const iface of Object.values(nets)) {
      for (const cfg of iface) {
        if (cfg.family === 'IPv4' && !cfg.internal) {
          ip = cfg.address;
          break;
        }
      }
      if (ip) break;
    }
  } catch { /* ignore */ }

  sendJson(res, {
    hostname,
    ip,
    uptime: uptimeSec,
    os: prettyName,
    serverName: SERVER_NAME,
  });
}

async function handleResources(req, res) {
  const cpu = getCpuUsage();
  const mem = getMemInfo();
  const disk = getDisk();
  sendJson(res, { cpu, ram: mem.ram, swap: mem.swap, disk });
}

async function handleContainers(req, res) {
  try {
    const result = await dockerRequest('GET', '/containers/json?all=true');
    const containers = (result.data || []).map((c) => ({
      id: c.Id,
      name: (c.Names && c.Names[0] || '').replace(/^\//, ''),
      image: c.Image,
      state: c.State,
      status: c.Status,
      health: c.State === 'running'
        ? (c.Status || '').toLowerCase().includes('healthy')
          ? 'healthy'
          : (c.Status || '').toLowerCase().includes('unhealthy')
            ? 'unhealthy'
            : 'running'
        : c.State,
    }));
    sendJson(res, containers);
  } catch (err) {
    sendJson(res, { error: 'Failed to reach Docker daemon', details: err.message }, 502);
  }
}

async function handleContainerLogs(req, res, containerId, query) {
  if (!isValidContainerId(containerId)) {
    return sendJson(res, { error: 'Invalid container ID' }, 400);
  }
  const lines = sanitizeLines(query.lines);
  try {
    const result = await dockerRequestRaw(
      'GET',
      `/containers/${containerId}/logs?stdout=true&stderr=true&tail=${lines}&timestamps=true`
    );
    // Strip Docker log frame headers (8-byte prefix per line)
    const cleaned = result.data
      .split('\n')
      .map((line) => {
        if (line.length > 8) {
          const byte0 = line.charCodeAt(0);
          if (byte0 === 1 || byte0 === 2) return line.slice(8);
        }
        return line;
      })
      .join('\n');
    sendJson(res, { logs: cleaned });
  } catch (err) {
    sendJson(res, { error: 'Failed to fetch logs', details: err.message }, 502);
  }
}

async function handleContainerRestart(req, res, containerId) {
  if (!isValidContainerId(containerId)) {
    return sendJson(res, { error: 'Invalid container ID' }, 400);
  }
  try {
    const result = await dockerRequest('POST', `/containers/${containerId}/restart?t=10`);
    const ok = result.status === 204;
    audit(req, 'container.restart', containerId.slice(0, 12), ok ? 'ok' : 'fail', { status: result.status });
    sendJson(res, { success: ok, status: result.status });
  } catch (err) {
    audit(req, 'container.restart', containerId.slice(0, 12), 'error', { error: err.message });
    sendJson(res, { error: 'Failed to restart container', details: err.message }, 502);
  }
}

async function handleContainerStop(req, res, containerId) {
  if (!isValidContainerId(containerId)) {
    return sendJson(res, { error: 'Invalid container ID' }, 400);
  }
  try {
    const result = await dockerRequest('POST', `/containers/${containerId}/stop?t=10`);
    const ok = result.status === 204 || result.status === 304;
    audit(req, 'container.stop', containerId.slice(0, 12), ok ? 'ok' : 'fail', { status: result.status });
    sendJson(res, { success: ok, status: result.status });
  } catch (err) {
    audit(req, 'container.stop', containerId.slice(0, 12), 'error', { error: err.message });
    sendJson(res, { error: 'Failed to stop container', details: err.message }, 502);
  }
}

async function handleContainerStart(req, res, containerId) {
  if (!isValidContainerId(containerId)) {
    return sendJson(res, { error: 'Invalid container ID' }, 400);
  }
  try {
    const result = await dockerRequest('POST', `/containers/${containerId}/start`);
    const ok = result.status === 204 || result.status === 304;
    audit(req, 'container.start', containerId.slice(0, 12), ok ? 'ok' : 'fail', { status: result.status });
    sendJson(res, { success: ok, status: result.status });
  } catch (err) {
    audit(req, 'container.start', containerId.slice(0, 12), 'error', { error: err.message });
    sendJson(res, { error: 'Failed to start container', details: err.message }, 502);
  }
}

async function handleRestartAll(req, res) {
  try {
    const result = await dockerRequest('GET', '/containers/json?all=true');
    const containers = (result.data || []).filter(
      (c) => c.Labels && c.Labels['com.docker.compose.project'] === 'supabase'
    );
    const results = [];
    for (const c of containers) {
      try {
        const r = await dockerRequest('POST', `/containers/${c.Id}/restart?t=10`);
        results.push({ id: c.Id, name: (c.Names[0] || '').replace(/^\//, ''), success: r.status === 204 });
      } catch (err) {
        results.push({ id: c.Id, name: (c.Names[0] || '').replace(/^\//, ''), success: false, error: err.message });
      }
    }
    const okCount = results.filter(r => r.success).length;
    audit(req, 'container.restart-all', '*', 'ok', { total: results.length, ok: okCount });
    sendJson(res, { results });
  } catch (err) {
    audit(req, 'container.restart-all', '*', 'error', { error: err.message });
    sendJson(res, { error: 'Failed to restart containers', details: err.message }, 502);
  }
}

async function handleBackupSnapshots(req, res) {
  try {
    const repo = process.env.RESTIC_REPOSITORY || '/backup';
    const { stdout } = await execAsync(`restic -r ${repo} snapshots --json 2>/dev/null || echo "[]"`, {
      env: { ...process.env, RESTIC_REPOSITORY: repo },
    });
    const snapshots = JSON.parse(stdout || '[]');
    sendJson(res, snapshots);
  } catch {
    sendJson(res, []);
  }
}

async function handleBackupStatus(req, res) {
  // Primary: read backup-status.json written by backup script
  const statusPath = path.join('/supabase', 'backup-status.json');
  let statusData = null;
  try {
    const raw = fs.readFileSync(statusPath, 'utf8');
    statusData = JSON.parse(raw);
  } catch { /* file may not exist yet */ }

  // Fallback: parse log file for line count
  let logLines = 0;
  try {
    const logFile = fs.readdirSync(HOST_LOGS).find(f => f.startsWith('supabase-backup-')) || 'backup.log';
    const logPath = path.join(HOST_LOGS, logFile);
    const log = readFile(logPath);
    const lines = log.trim().split('\n').filter(Boolean);
    logLines = lines.length;
  } catch {}

  sendJson(res, {
    success: statusData?.success ?? null,
    timestamp: statusData?.timestamp ?? null,
    started: statusData?.started ?? null,
    durationSeconds: statusData?.duration_seconds ?? null,
    dumpSizeBytes: statusData?.dump_size_bytes ?? null,
    snapshotId: statusData?.snapshot_id ?? null,
    error: statusData?.error ?? null,
    serverName: statusData?.server_name ?? null,
    logLines: logLines,
    hasStatusFile: statusData !== null,
  });
}

async function handleLogsFile(req, res, filename) {
  const allowed = {
    deploy: 'supabase-deploy.log',
    backup: fs.readdirSync(HOST_LOGS).find(f => f.startsWith('supabase-backup-')) || 'backup.log',
  };
  const file = allowed[filename];
  if (!file) return sendJson(res, { error: 'Unknown log file' }, 404);
  const logPath = path.join(HOST_LOGS, file);
  const content = readFile(logPath);
  const lines = content.split('\n');
  const tail = lines.slice(-500).join('\n');
  sendJson(res, { log: tail, totalLines: lines.length });
}

async function handleSecurityFail2ban(req, res) {
  const logPath = path.join(HOST_LOGS, 'fail2ban.log');
  const log = readFile(logPath);
  const banned = [];
  const lines = log.split('\n');
  for (const line of lines) {
    const banMatch = line.match(/Ban\s+(\d+\.\d+\.\d+\.\d+)/);
    if (banMatch) {
      const timeMatch = line.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/);
      banned.push({ ip: banMatch[1], time: timeMatch ? timeMatch[1] : 'Unknown' });
    }
  }
  const unbanned = new Set();
  for (const line of lines) {
    const unbanMatch = line.match(/Unban\s+(\d+\.\d+\.\d+\.\d+)/);
    if (unbanMatch) unbanned.add(unbanMatch[1]);
  }
  const active = banned.filter((b) => !unbanned.has(b.ip));
  sendJson(res, { banned: active, total: banned.length });
}

// --- Upgrade / Tags / Dumps ---

const TOP_ENV_PATH = path.join(SUPABASE_DIR, '.env');

function readTopEnv() {
  try {
    return parseEnvFile(fs.readFileSync(TOP_ENV_PATH, 'utf8'));
  } catch {
    return new Map();
  }
}

function httpsGetJson(host, reqPath) {
  return new Promise((resolve, reject) => {
    const https = require('https');
    const req = https.request({
      hostname: host,
      path: reqPath,
      method: 'GET',
      headers: { 'User-Agent': 'SupaFast/1.0', Accept: 'application/json' },
      timeout: 10000,
    }, (r) => {
      let data = '';
      r.on('data', (c) => (data += c));
      r.on('end', () => {
        try { resolve({ status: r.statusCode, data: data ? JSON.parse(data) : null }); }
        catch { resolve({ status: r.statusCode, data: null }); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.end();
  });
}

async function handleUpgradeTags(req, res, service) {
  if (!UPGRADABLE_SERVICES.has(service)) {
    return sendJson(res, { error: 'Service not upgradable via panel' }, 400);
  }
  const repo = SERVICE_TO_REPO[service];
  try {
    const r = await httpsGetJson('hub.docker.com', `/v2/repositories/${repo}/tags/?page_size=50&ordering=last_updated`);
    if (r.status !== 200 || !r.data || !Array.isArray(r.data.results)) {
      return sendJson(res, { error: 'Docker Hub unavailable', status: r.status }, 502);
    }
    const env = readTopEnv();
    const currentImage = env.get(imageEnvKey(service)) || '';
    const currentTag = currentImage.includes(':') ? currentImage.split(':').slice(1).join(':') : '';
    const tags = r.data.results
      .map((t) => ({ name: t.name, lastUpdated: t.last_updated, size: t.full_size }))
      .filter((t) => isPinnableTag(t.name));
    sendJson(res, { service, repo, currentTag, currentImage, tags });
  } catch (err) {
    sendJson(res, { error: 'Tag fetch failed', details: err.message }, 502);
  }
}

function imageEnvKey(service) {
  const map = {
    studio: 'IMAGE_STUDIO', kong: 'IMAGE_KONG', auth: 'IMAGE_AUTH',
    rest: 'IMAGE_REST', realtime: 'IMAGE_REALTIME', storage: 'IMAGE_STORAGE',
    imgproxy: 'IMAGE_IMGPROXY', meta: 'IMAGE_META', functions: 'IMAGE_FUNCTIONS',
    analytics: 'IMAGE_LOGFLARE', vector: 'IMAGE_VECTOR', supavisor: 'IMAGE_SUPAVISOR',
  };
  return map[service];
}

async function handleUpgradeStart(req, res, service) {
  if (!UPGRADABLE_SERVICES.has(service)) {
    return sendJson(res, { error: 'Service not upgradable' }, 400);
  }
  const body = await readBody(req);
  const target = typeof body.target === 'string' ? body.target : '';
  if (!TAG_RE.test(target)) {
    return sendJson(res, { error: 'Invalid tag format' }, 400);
  }
  if (!isPinnableTag(target)) {
    return sendJson(res, { error: 'Refusing to pin a floating tag (latest/main/edge/latest_arm64/etc.) — pick a versioned tag' }, 400);
  }

  try {
    if (!fs.existsSync(UPGRADE_DIR)) {
      return sendJson(res, { error: 'Upgrade directory not mounted' }, 500);
    }
    const resultPath = path.join(UPGRADE_DIR, 'result.json');
    if (fs.existsSync(resultPath)) {
      try {
        const prev = JSON.parse(fs.readFileSync(resultPath, 'utf8'));
        if (prev && prev.status === 'pending') {
          return sendJson(res, { error: 'Another upgrade is in progress' }, 409);
        }
      } catch {}
    }

    const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    let fromImage = '';
    try {
      const env = readTopEnv();
      fromImage = env.get(imageEnvKey(service)) || '';
    } catch {}
    const pending = { id, status: 'pending', service, from: fromImage, to: target, message: 'queued', at: new Date().toISOString() };
    fs.writeFileSync(resultPath, JSON.stringify(pending));

    // Atomic write: write to tmp then rename so path unit sees one PathModified.
    const reqPath = path.join(UPGRADE_DIR, 'request.json');
    const tmp = reqPath + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify({ id, action: 'upgrade', service, target, at: new Date().toISOString() }));
    fs.renameSync(tmp, reqPath);

    audit(req, 'upgrade.start', service, 'queued', { target, from: fromImage, id });
    sendJson(res, { success: true, id });
  } catch (err) {
    sendJson(res, { error: 'Failed to queue upgrade', details: err.message }, 500);
  }
}

// Service→container-name map; matches the map in supabase-upgrade.sh.
const SERVICE_TO_CONTAINER = {
  functions: 'supabase-edge-functions',
  realtime: 'realtime-dev.supabase-realtime',
  supavisor: 'supabase-pooler',
};
function containerNameFor(service) {
  return SERVICE_TO_CONTAINER[service] || `supabase-${service}`;
}

async function handleImageDigests(req, res) {
  // For each upgradable service, returns {service, image, isPinned, digest, shortDigest}.
  // Digest is the sha256 of the local image (from container .Image). If the
  // env value contains '@sha256:' we consider it pinned.
  const out = [];
  try {
    const env = readTopEnv();
    for (const service of UPGRADABLE_SERVICES) {
      const image = env.get(imageEnvKey(service)) || '';
      const isPinned = image.includes('@sha256:');
      let digest = '';
      try {
        const cname = containerNameFor(service);
        const r = await dockerRequest('GET', `/containers/${encodeURIComponent(cname)}/json`);
        if (r.status === 200 && r.data && r.data.Image) digest = r.data.Image;
      } catch {}
      out.push({ service, image, isPinned, digest, shortDigest: digest ? digest.slice(7, 19) : '' });
    }
    sendJson(res, { services: out });
  } catch (e) {
    sendJson(res, { error: 'Failed to list image digests', details: e.message }, 500);
  }
}

async function handleImagePin(req, res) {
  try {
    if (!fs.existsSync(UPGRADE_DIR)) return sendJson(res, { error: 'Upgrade directory not mounted' }, 500);
    const resultPath = path.join(UPGRADE_DIR, 'pin-result.json');
    if (fs.existsSync(resultPath)) {
      try { const prev = JSON.parse(fs.readFileSync(resultPath, 'utf8')); if (prev && prev.status === 'pending') return sendJson(res, { error: 'Pin job already in progress' }, 409); } catch {}
    }
    const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    fs.writeFileSync(resultPath, JSON.stringify({ id, status: 'pending', at: new Date().toISOString() }));
    const reqPath = path.join(UPGRADE_DIR, 'pin-request.json');
    const tmp = reqPath + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify({ id, action: 'pin-digests', at: new Date().toISOString() }));
    fs.renameSync(tmp, reqPath);
    audit(req, 'pin-images', 'all', 'queued', { id });
    sendJson(res, { success: true, id });
  } catch (e) {
    sendJson(res, { error: 'Failed to queue pin', details: e.message }, 500);
  }
}

async function handleUpgradeStatus(req, res) {
  try {
    const resultPath = path.join(UPGRADE_DIR, 'result.json');
    if (!fs.existsSync(resultPath)) {
      return sendJson(res, { status: 'idle' });
    }
    const result = JSON.parse(fs.readFileSync(resultPath, 'utf8'));
    sendJson(res, result);
  } catch (err) {
    sendJson(res, { status: 'unknown', error: err.message });
  }
}

async function handleUpgradeCurrent(req, res) {
  const env = readTopEnv();
  const services = {};
  for (const svc of UPGRADABLE_SERVICES) {
    const img = env.get(imageEnvKey(svc)) || '';
    const tag = img.includes(':') ? img.split(':').slice(1).join(':') : '';
    services[svc] = { image: img, tag, repo: SERVICE_TO_REPO[svc] };
  }
  sendJson(res, { services });
}

async function handlePreUpgradeDumps(req, res) {
  try {
    const dir = path.join(HOST_BACKUPS, 'pre-upgrade');
    if (!fs.existsSync(dir)) return sendJson(res, { dumps: [] });
    const files = fs.readdirSync(dir)
      .filter((f) => f.endsWith('.sql.gz'))
      .map((f) => {
        const st = fs.statSync(path.join(dir, f));
        return { name: f, size: st.size, mtime: st.mtime.toISOString() };
      })
      .sort((a, b) => b.mtime.localeCompare(a.mtime));
    sendJson(res, { dumps: files });
  } catch (err) {
    sendJson(res, { error: err.message }, 500);
  }
}

async function handleUpgradeLog(req, res, which) {
  const files = { log: 'upgrade.log', failure: 'last-failure.log' };
  const name = files[which];
  if (!name) return sendJson(res, { error: 'Unknown log' }, 404);
  try {
    const p = path.join(UPGRADE_DIR, name);
    if (!fs.existsSync(p)) return sendJson(res, { log: '', exists: false });
    const content = fs.readFileSync(p, 'utf8');
    const lines = content.split('\n');
    const tail = lines.slice(-500).join('\n');
    sendJson(res, { log: tail, totalLines: lines.length, exists: true });
  } catch (err) {
    sendJson(res, { error: err.message }, 500);
  }
}

const ROTATE_REQ = () => path.join(UPGRADE_DIR, 'rotate-request.json');
const ROTATE_RES = () => path.join(UPGRADE_DIR, 'rotate-result.json');
const ROTATE_STATE = () => path.join(UPGRADE_DIR, 'rotation-state.json');

function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function generateKeyBundle() {
  const { webcrypto } = require('crypto');
  const keyPair = await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
  );
  const [privJwk, pubJwk] = await Promise.all([
    webcrypto.subtle.exportKey('jwk', keyPair.privateKey),
    webcrypto.subtle.exportKey('jwk', keyPair.publicKey),
  ]);
  const kid = webcrypto.randomUUID();
  const base = { kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig', kid };
  const rand = webcrypto.getRandomValues(new Uint8Array(30));
  return {
    kid,
    private_jwk: { ...base, x: privJwk.x, y: privJwk.y, d: privJwk.d },
    public_jwk: { ...base, x: pubJwk.x, y: pubJwk.y },
    publishable_key: 'sb_publishable_' + b64url(rand),
    secret_key: 'sb_secret_' + b64url(webcrypto.getRandomValues(new Uint8Array(30))),
    created_at: new Date().toISOString(),
  };
}

function checkRotationIdle() {
  try {
    const prev = JSON.parse(fs.readFileSync(ROTATE_RES(), 'utf8'));
    if (prev && prev.status === 'pending') return false;
  } catch {}
  return true;
}

async function handleRotateKeys(req, res) {
  if (!checkRotationIdle()) return sendJson(res, { error: 'Rotation in progress' }, 409);
  try {
    const bundle = await generateKeyBundle();
    const id = `rot-${Date.now().toString(36)}`;
    fs.writeFileSync(ROTATE_RES(), JSON.stringify({ id, status: 'pending', action: 'rotate', kid: bundle.kid, at: new Date().toISOString() }));
    const tmp = ROTATE_REQ() + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify({ id, action: 'rotate', bundle, at: new Date().toISOString() }));
    fs.renameSync(tmp, ROTATE_REQ());
    // One-time display: user must save these; opaque keys aren't recoverable from state file after this response
    sendJson(res, {
      success: true,
      id,
      kid: bundle.kid,
      publishable_key: bundle.publishable_key,
      secret_key: bundle.secret_key,
      warning: 'Save these now. They are applied server-side once rotation completes (~5s).',
    });
  } catch (err) {
    sendJson(res, { error: 'Rotation failed', details: err.message }, 500);
  }
}

async function handleRotateStatus(req, res) {
  try {
    if (!fs.existsSync(ROTATE_RES())) return sendJson(res, { status: 'idle' });
    sendJson(res, JSON.parse(fs.readFileSync(ROTATE_RES(), 'utf8')));
  } catch (err) {
    sendJson(res, { status: 'unknown', error: err.message });
  }
}

function readInitialKeyFromEnv() {
  // On a fresh deploy, rotation-state.json doesn't exist yet — the host script
  // only creates it on the first rotate/finalize. Synthesize a single-entry
  // view from .env so the Keys tab shows the deploy-time kid instead of "No
  // active new-format keys". Returns null if .env lacks new-format material.
  try {
    const envPath = path.join(SUPABASE_DIR, '.env');
    if (!fs.existsSync(envPath)) return null;
    const env = {};
    for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
      const m = line.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/);
      if (!m) continue;
      let v = m[2];
      if ((v.startsWith("'") && v.endsWith("'")) || (v.startsWith('"') && v.endsWith('"'))) v = v.slice(1, -1);
      env[m[1]] = v;
    }
    const jwtKeys = JSON.parse(env.JWT_KEYS || '[]');
    const ec = jwtKeys.find((k) => k && k.kty === 'EC');
    if (!ec || !ec.kid) return null;
    return {
      kid: ec.kid,
      created_at: 'deploy',
      publishable_prefix: (env.SUPABASE_PUBLISHABLE_KEY || '').slice(0, 24) + '…',
    };
  } catch {
    return null;
  }
}

function handleKeysCurrent(req, res) {
  try {
    const envPath = path.join(SUPABASE_DIR, '.env');
    const env = {};
    for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
      const m = line.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/);
      if (!m) continue;
      let v = m[2];
      if ((v.startsWith("'") && v.endsWith("'")) || (v.startsWith('"') && v.endsWith('"'))) v = v.slice(1, -1);
      env[m[1]] = v;
    }
    sendJson(res, {
      url: env.SITE_URL || env.API_EXTERNAL_URL || '',
      publishable_key: env.SUPABASE_PUBLISHABLE_KEY || '',
      secret_key: env.SUPABASE_SECRET_KEY || '',
      anon_key: env.ANON_KEY || '',
      service_role_key: env.SERVICE_ROLE_KEY || '',
    });
  } catch (err) {
    sendJson(res, { error: err.message }, 500);
  }
}

async function handleRotateState(req, res) {
  try {
    if (!fs.existsSync(ROTATE_STATE())) {
      const seed = readInitialKeyFromEnv();
      return sendJson(res, { active_keys: seed ? [seed] : [], seeded: false });
    }
    const state = JSON.parse(fs.readFileSync(ROTATE_STATE(), 'utf8'));
    const safe = (state.active_keys || []).map((k) => ({
      kid: k.kid,
      created_at: k.created_at,
      publishable_prefix: (k.publishable_key || '').slice(0, 24) + '…',
    }));
    sendJson(res, { active_keys: safe, seeded: true });
  } catch (err) {
    sendJson(res, { error: err.message }, 500);
  }
}

async function handleRotateFinalize(req, res, kid) {
  if (!/^[a-f0-9-]{8,64}$/i.test(kid)) return sendJson(res, { error: 'Invalid kid' }, 400);
  if (!checkRotationIdle()) return sendJson(res, { error: 'Rotation in progress' }, 409);
  try {
    const state = fs.existsSync(ROTATE_STATE())
      ? JSON.parse(fs.readFileSync(ROTATE_STATE(), 'utf8'))
      : { active_keys: [] };
    if ((state.active_keys || []).length <= 1) {
      return sendJson(res, { error: 'Cannot remove the only active key — rotate first' }, 400);
    }
    if (!state.active_keys.some((k) => k.kid === kid)) {
      return sendJson(res, { error: 'kid not found in active set' }, 404);
    }
    const id = `fin-${Date.now().toString(36)}`;
    fs.writeFileSync(ROTATE_RES(), JSON.stringify({ id, status: 'pending', action: 'finalize', kid, at: new Date().toISOString() }));
    const tmp = ROTATE_REQ() + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify({ id, action: 'finalize', kid, at: new Date().toISOString() }));
    fs.renameSync(tmp, ROTATE_REQ());
    sendJson(res, { success: true, id, kid });
  } catch (err) {
    sendJson(res, { error: 'Finalize failed', details: err.message }, 500);
  }
}

// --- Response Helpers ---

function sendJson(res, data, status = 200) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-cache',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(body);
}

function serveStatic(req, res, urlPath) {
  let filePath = path.join(__dirname, 'public', urlPath === '/' ? 'index.html' : urlPath);
  filePath = path.resolve(filePath);

  // Prevent directory traversal
  if (!filePath.startsWith(path.join(__dirname, 'public'))) {
    res.writeHead(403);
    return res.end('Forbidden');
  }

  const ext = path.extname(filePath);
  const contentType = MIME[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      return res.end('Not Found');
    }
    // Inject SERVER_NAME for index.html
    if (ext === '.html') {
      const html = data.toString().replace(/\{\{SERVER_NAME\}\}/g, SERVER_NAME);
      res.writeHead(200, { 'Content-Type': contentType });
      return res.end(html);
    }
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
}

// --- URL Parsing ---

function parseUrl(raw) {
  const [pathPart, queryPart] = raw.split('?');
  const query = {};
  if (queryPart) {
    queryPart.split('&').forEach((pair) => {
      const [k, v] = pair.split('=');
      if (k) query[decodeURIComponent(k)] = decodeURIComponent(v || '');
    });
  }
  return { path: pathPart, query };
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (chunk) => (data += chunk));
    req.on('end', () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch {
        resolve({});
      }
    });
  });
}

// --- Router ---

const server = http.createServer(async (req, res) => {
  const { path: urlPath, query } = parseUrl(req.url);
  const method = req.method;

  try {
    // Defense-in-depth: all /api/* must carry the shared secret injected by
    // Caddy. Prevents other containers on management-net from bypassing
    // Authelia by hitting management:3001 directly.
    if (PROXY_SECRET && urlPath.startsWith('/api/')) {
      if (req.headers['x-proxy-secret'] !== PROXY_SECRET) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Unauthorized' }));
      }
    }

    // CSRF protection: require X-Requested-With header on all mutating requests
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
      if (req.headers['x-requested-with'] !== 'XMLHttpRequest') {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Forbidden: missing required header' }));
      }
    }

    // Rate limit all /api/* (after auth so unauth attacks can't affect legit users)
    if (urlPath.startsWith('/api/') && !rateLimit(req, method)) {
      res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '30' });
      return res.end(JSON.stringify({ error: 'Rate limit exceeded', limit: (['POST','PUT','DELETE','PATCH'].includes(method) ? '10/min' : '120/min') }));
    }

    // API routes
    if (urlPath === '/api/system' && method === 'GET') {
      return handleSystem(req, res);
    }
    if (urlPath === '/api/resources' && method === 'GET') {
      return handleResources(req, res);
    }
    if (urlPath === '/api/containers' && method === 'GET') {
      return handleContainers(req, res);
    }
    if (urlPath === '/api/containers/restart-all' && method === 'POST') {
      return handleRestartAll(req, res);
    }

    // Container-specific routes
    const containerLogsMatch = urlPath.match(/^\/api\/containers\/([a-f0-9]+)\/logs$/i);
    if (containerLogsMatch && method === 'GET') {
      return handleContainerLogs(req, res, containerLogsMatch[1], query);
    }
    const containerRestartMatch = urlPath.match(/^\/api\/containers\/([a-f0-9]+)\/restart$/i);
    if (containerRestartMatch && method === 'POST') {
      return handleContainerRestart(req, res, containerRestartMatch[1]);
    }
    const containerStopMatch = urlPath.match(/^\/api\/containers\/([a-f0-9]+)\/stop$/i);
    if (containerStopMatch && method === 'POST') {
      return handleContainerStop(req, res, containerStopMatch[1]);
    }
    const containerStartMatch = urlPath.match(/^\/api\/containers\/([a-f0-9]+)\/start$/i);
    if (containerStartMatch && method === 'POST') {
      return handleContainerStart(req, res, containerStartMatch[1]);
    }

    // Backup routes
    if (urlPath === '/api/backup/snapshots' && method === 'GET') {
      return handleBackupSnapshots(req, res);
    }
    if (urlPath === '/api/backup/status' && method === 'GET') {
      return handleBackupStatus(req, res);
    }

    // Security routes
    if (urlPath === '/api/security/fail2ban' && method === 'GET') {
      return handleSecurityFail2ban(req, res);
    }

    // Secrets routes
    if (urlPath === '/api/secrets' && method === 'GET') {
      return handleGetSecrets(req, res);
    }
    if (urlPath === '/api/secrets' && method === 'POST') {
      return handleSetSecret(req, res);
    }
    const secretDeleteMatch = urlPath.match(/^\/api\/secrets\/([A-Za-z_][A-Za-z0-9_]*)$/);
    if (secretDeleteMatch && method === 'DELETE') {
      return handleDeleteSecret(req, res, secretDeleteMatch[1]);
    }

    // Upgrade routes
    if (urlPath === '/api/upgrade/current' && method === 'GET') {
      return handleUpgradeCurrent(req, res);
    }
    if (urlPath === '/api/upgrade/status' && method === 'GET') {
      return handleUpgradeStatus(req, res);
    }
    if (urlPath === '/api/upgrade/dumps' && method === 'GET') {
      return handlePreUpgradeDumps(req, res);
    }
    if (urlPath === '/api/upgrade/log' && method === 'GET') {
      return handleUpgradeLog(req, res, 'log');
    }
    if (urlPath === '/api/upgrade/last-failure' && method === 'GET') {
      return handleUpgradeLog(req, res, 'failure');
    }
    const tagsMatch = urlPath.match(/^\/api\/upgrade\/tags\/([a-z]+)$/);
    if (tagsMatch && method === 'GET') {
      return handleUpgradeTags(req, res, tagsMatch[1]);
    }
    const upgradeStartMatch = urlPath.match(/^\/api\/upgrade\/([a-z]+)$/);
    if (upgradeStartMatch && method === 'POST') {
      return handleUpgradeStart(req, res, upgradeStartMatch[1]);
    }

    // Key rotation
    if (urlPath === '/api/rotate-keys' && method === 'POST') {
      return handleRotateKeys(req, res);
    }
    if (urlPath === '/api/rotate-keys/status' && method === 'GET') {
      return handleRotateStatus(req, res);
    }
    if (urlPath === '/api/rotate-keys/state' && method === 'GET') {
      return handleRotateState(req, res);
    }
    if (urlPath === '/api/keys/current' && method === 'GET') {
      return handleKeysCurrent(req, res);
    }
    const finalizeMatch = urlPath.match(/^\/api\/rotate-keys\/finalize\/([a-f0-9-]+)$/i);
    if (finalizeMatch && method === 'POST') {
      return handleRotateFinalize(req, res, finalizeMatch[1]);
    }

    // Audit log (read-only tail)
    if (urlPath === '/api/audit' && method === 'GET') {
      try {
        const limit = Math.min(parseInt(query.limit || '200', 10) || 200, 1000);
        if (!fs.existsSync(AUDIT_LOG_PATH)) return sendJson(res, { entries: [] });
        const raw = fs.readFileSync(AUDIT_LOG_PATH, 'utf8');
        const lines = raw.split('\n').filter(Boolean);
        const entries = lines.slice(-limit).reverse().map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
        return sendJson(res, { entries });
      } catch (e) {
        return sendJson(res, { error: 'Failed to read audit log' }, 500);
      }
    }

    // Image digest endpoints (for pinning)
    if (urlPath === '/api/images/digests' && method === 'GET') {
      return handleImageDigests(req, res);
    }
    if (urlPath === '/api/images/pin' && method === 'POST') {
      return handleImagePin(req, res);
    }

    // Log routes
    if (urlPath === '/api/logs/deploy' && method === 'GET') {
      return handleLogsFile(req, res, 'deploy');
    }
    if (urlPath === '/api/logs/backup' && method === 'GET') {
      return handleLogsFile(req, res, 'backup');
    }

    // Static files
    serveStatic(req, res, urlPath);
  } catch (err) {
    console.error('Unhandled error:', err);
    sendJson(res, { error: 'Internal server error' }, 500);
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Supabase Management Panel running on port ${PORT}`);
});
