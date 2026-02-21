const http = require('http');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

const PORT = process.env.PORT || 3001;
const SUPABASE_DIR = process.env.SUPABASE_DIR || '/opt/supabase';
const SERVER_NAME = process.env.SERVER_NAME || 'Supabase Server';
const DOCKER_HOST = process.env.DOCKER_HOST || 'tcp://localhost:2375';
const HOST_LOGS = '/host-logs';

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
    const { restarted } = await restartEdgeFunctionsContainer();
    sendJson(res, { success: true, action: existed ? 'updated' : 'created', key, restarted });
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
    const { restarted } = await restartEdgeFunctionsContainer();
    sendJson(res, { success: true, key, restarted });
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
    sendJson(res, { success: result.status === 204, status: result.status });
  } catch (err) {
    sendJson(res, { error: 'Failed to restart container', details: err.message }, 502);
  }
}

async function handleContainerStop(req, res, containerId) {
  if (!isValidContainerId(containerId)) {
    return sendJson(res, { error: 'Invalid container ID' }, 400);
  }
  try {
    const result = await dockerRequest('POST', `/containers/${containerId}/stop?t=10`);
    sendJson(res, { success: result.status === 204 || result.status === 304, status: result.status });
  } catch (err) {
    sendJson(res, { error: 'Failed to stop container', details: err.message }, 502);
  }
}

async function handleContainerStart(req, res, containerId) {
  if (!isValidContainerId(containerId)) {
    return sendJson(res, { error: 'Invalid container ID' }, 400);
  }
  try {
    const result = await dockerRequest('POST', `/containers/${containerId}/start`);
    sendJson(res, { success: result.status === 204 || result.status === 304, status: result.status });
  } catch (err) {
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
    sendJson(res, { results });
  } catch (err) {
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
