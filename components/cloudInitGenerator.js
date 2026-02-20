// ─────────────────────────────────────────────────────────────────────────────
// Cloud-Init Generator — all configs inlined, no git/yq/sed
// ─────────────────────────────────────────────────────────────────────────────

// ── Tar archive creation (browser-side) ─────────────────────────────────────
// Minimal POSIX tar implementation for bundling static config files.
// Files are packed into a tar, gzipped via CompressionStream, then base64-encoded
// and embedded in the cloud-init script as a single payload.

function tarHeader(name, content) {
  const enc = new TextEncoder();
  const buf = new Uint8Array(512);
  const nameBytes = enc.encode(name);
  buf.set(nameBytes.slice(0, 100), 0); // name (100 bytes)
  writeOctal(buf, 100, 0o644, 8);      // mode
  writeOctal(buf, 108, 0, 8);          // uid
  writeOctal(buf, 116, 0, 8);          // gid
  writeOctal(buf, 124, content.length, 12); // size
  writeOctal(buf, 136, Math.floor(Date.now() / 1000), 12); // mtime
  buf.set(enc.encode('        '), 148); // checksum placeholder (8 spaces)
  buf[156] = 0x30; // typeflag: '0' = regular file
  // Compute checksum
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += buf[i];
  const cksum = sum.toString(8).padStart(6, '0') + '\0 ';
  buf.set(enc.encode(cksum), 148);
  return buf;
}

function writeOctal(buf, offset, value, length) {
  const str = value.toString(8).padStart(length - 1, '0') + '\0';
  const enc = new TextEncoder();
  buf.set(enc.encode(str).slice(0, length), offset);
}

function createTar(files) {
  const enc = new TextEncoder();
  const parts = [];
  for (const { name, content } of files) {
    const data = enc.encode(content);
    parts.push(tarHeader(name, data));
    parts.push(data);
    // Pad to 512-byte boundary
    const remainder = data.length % 512;
    if (remainder > 0) parts.push(new Uint8Array(512 - remainder));
  }
  // Two 512-byte zero blocks to mark end of archive
  parts.push(new Uint8Array(1024));
  const total = parts.reduce((s, p) => s + p.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) { result.set(p, offset); offset += p.length; }
  return result;
}

async function gzipAndBase64(data) {
  const cs = new CompressionStream('gzip');
  const writer = cs.writable.getWriter();
  writer.write(data);
  writer.close();
  const reader = cs.readable.getReader();
  const chunks = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const total = chunks.reduce((s, c) => s + c.length, 0);
  const compressed = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { compressed.set(c, off); off += c.length; }
  // Base64 encode
  let binary = '';
  for (let i = 0; i < compressed.length; i++) {
    binary += String.fromCharCode(compressed[i]);
  }
  return btoa(binary);
}

// ── Static config file contents ─────────────────────────────────────────────
// These are packed into a tarball and extracted on the server.
// They do NOT need JS interpolation — any runtime variables use
// Docker Compose ${VAR} or tool-specific syntax (Kong $VAR, Vector ${VAR}, etc.)

function getKongYml(anonKey, serviceRoleKey, dashboardUsername, dashboardPassword) {
  return `_format_version: "2.1"
_transform: true

###
### Consumers / Users
###
consumers:
  - username: DASHBOARD
  - username: anon
    keyauth_credentials:
      - key: ${anonKey}
  - username: service_role
    keyauth_credentials:
      - key: ${serviceRoleKey}

###
### Access Control List
###
acls:
  - consumer: anon
    group: anon
  - consumer: service_role
    group: admin

###
### Dashboard credentials
###
basicauth_credentials:
  - consumer: DASHBOARD
    username: "${dashboardUsername}"
    password: "${dashboardPassword}"

###
### API Routes
###
services:
  ## Open Auth routes
  - name: auth-v1-open
    url: http://auth:9999/verify
    routes:
      - name: auth-v1-open
        strip_path: true
        paths:
          - /auth/v1/verify
    plugins:
      - name: cors
  - name: auth-v1-open-callback
    url: http://auth:9999/callback
    routes:
      - name: auth-v1-open-callback
        strip_path: true
        paths:
          - /auth/v1/callback
    plugins:
      - name: cors
  - name: auth-v1-open-authorize
    url: http://auth:9999/authorize
    routes:
      - name: auth-v1-open-authorize
        strip_path: true
        paths:
          - /auth/v1/authorize
    plugins:
      - name: cors

  ## Secure Auth routes
  - name: auth-v1
    _comment: 'GoTrue: /auth/v1/* -> http://auth:9999/*'
    url: http://auth:9999/
    routes:
      - name: auth-v1-all
        strip_path: true
        paths:
          - /auth/v1/
    plugins:
      - name: cors
      - name: key-auth
        config:
          hide_credentials: false
      - name: acl
        config:
          hide_groups_header: true
          allow:
            - admin
            - anon

  ## Secure REST routes
  - name: rest-v1
    _comment: 'PostgREST: /rest/v1/* -> http://rest:3000/*'
    url: http://rest:3000/
    routes:
      - name: rest-v1-all
        strip_path: true
        paths:
          - /rest/v1/
    plugins:
      - name: cors
      - name: key-auth
        config:
          hide_credentials: true
      - name: acl
        config:
          hide_groups_header: true
          allow:
            - admin
            - anon

  ## Secure GraphQL routes
  - name: graphql-v1
    _comment: 'PostgREST: /graphql/v1/* -> http://rest:3000/rpc/graphql'
    url: http://rest:3000/rpc/graphql
    routes:
      - name: graphql-v1-all
        strip_path: true
        paths:
          - /graphql/v1
    plugins:
      - name: cors
      - name: key-auth
        config:
          hide_credentials: true
      - name: request-transformer
        config:
          add:
            headers:
              - Content-Profile:graphql_public
      - name: acl
        config:
          hide_groups_header: true
          allow:
            - admin
            - anon

  ## Secure Realtime routes
  - name: realtime-v1-ws
    _comment: 'Realtime: /realtime/v1/* -> ws://realtime:4000/socket/*'
    url: http://realtime-dev.supabase-realtime:4000/socket
    protocol: ws
    routes:
      - name: realtime-v1-ws
        strip_path: true
        paths:
          - /realtime/v1/
    plugins:
      - name: cors
      - name: key-auth
        config:
          hide_credentials: false
      - name: acl
        config:
          hide_groups_header: true
          allow:
            - admin
            - anon
  - name: realtime-v1-rest
    _comment: 'Realtime: /realtime/v1/* -> ws://realtime:4000/socket/*'
    url: http://realtime-dev.supabase-realtime:4000/api
    protocol: http
    routes:
      - name: realtime-v1-rest
        strip_path: true
        paths:
          - /realtime/v1/api
    plugins:
      - name: cors
      - name: key-auth
        config:
          hide_credentials: false
      - name: acl
        config:
          hide_groups_header: true
          allow:
            - admin
            - anon
  ## Storage routes: the storage server manages its own auth
  - name: storage-v1
    _comment: 'Storage: /storage/v1/* -> http://storage:5000/*'
    url: http://storage:5000/
    routes:
      - name: storage-v1-all
        strip_path: true
        paths:
          - /storage/v1/
    plugins:
      - name: cors

  ## Edge Functions routes
  - name: functions-v1
    _comment: 'Edge Functions: /functions/v1/* -> http://functions:9000/*'
    url: http://functions:9000/
    routes:
      - name: functions-v1-all
        strip_path: true
        paths:
          - /functions/v1/
    plugins:
      - name: cors

  ## Secure Database routes
  - name: meta
    _comment: 'pg-meta: /pg/* -> http://pg-meta:8080/*'
    url: http://meta:8080/
    routes:
      - name: meta-all
        strip_path: true
        paths:
          - /pg/
    plugins:
      - name: key-auth
        config:
          hide_credentials: false
      - name: acl
        config:
          hide_groups_header: true
          allow:
            - admin

  ## Block access to /api/mcp
  - name: mcp-blocker
    _comment: 'Block direct access to /api/mcp'
    url: http://supabase-studio:3000/api/mcp
    routes:
      - name: mcp-blocker-route
        strip_path: true
        paths:
          - /api/mcp
    plugins:
      - name: request-termination
        config:
          status_code: 403
          message: "Access is forbidden."

  ## MCP endpoint - local access
  - name: mcp
    _comment: 'MCP: /mcp -> http://supabase-studio:3000/api/mcp (local access)'
    url: http://supabase-studio:3000/api/mcp
    routes:
      - name: mcp
        strip_path: true
        paths:
          - /mcp
    plugins:
      - name: request-termination
        config:
          status_code: 403
          message: "Access is forbidden."

  ## Protected Dashboard - catch all remaining routes
  - name: dashboard
    _comment: 'Studio: /* -> http://supabase-studio:3000/*'
    url: http://supabase-studio:3000/
    routes:
      - name: dashboard-all
        strip_path: true
        paths:
          - /
    plugins:
      - name: cors
`;
}

function getVectorYml() {
  return `api:
  enabled: true
  address: 0.0.0.0:9001

sources:
  docker_host:
    type: docker_logs
    exclude_containers:
      - supabase-vector

transforms:
  project_logs:
    type: remap
    inputs:
      - docker_host
    source: |-
      .project = "default"
      .event_message = del(.message)
      .appname = del(.container_name)
      del(.container_created_at)
      del(.container_id)
      del(.source_type)
      del(.stream)
      del(.label)
      del(.image)
      del(.host)
      del(.stream)
  router:
    type: route
    inputs:
      - project_logs
    route:
      kong: '.appname == "supabase-kong"'
      auth: '.appname == "supabase-auth"'
      rest: '.appname == "supabase-rest"'
      realtime: '.appname == "realtime-dev.supabase-realtime"'
      storage: '.appname == "supabase-storage"'
      functions: '.appname == "supabase-edge-functions"'
      db: '.appname == "supabase-db"'
  kong_logs:
    type: remap
    inputs:
      - router.kong
    source: |-
      req, err = parse_nginx_log(.event_message, "combined")
      if err == null {
          .timestamp = req.timestamp
          .metadata.request.headers.referer = req.referer
          .metadata.request.headers.user_agent = req.agent
          .metadata.request.headers.cf_connecting_ip = req.client
          .metadata.request.method = req.method
          .metadata.request.path = req.path
          .metadata.request.protocol = req.protocol
          .metadata.response.status_code = req.status
      }
      if err != null {
        abort
      }
  kong_err:
    type: remap
    inputs:
      - router.kong
    source: |-
      .metadata.request.method = "GET"
      .metadata.response.status_code = 200
      parsed, err = parse_nginx_log(.event_message, "error")
      if err == null {
          .timestamp = parsed.timestamp
          .severity = parsed.severity
          .metadata.request.host = parsed.host
          .metadata.request.headers.cf_connecting_ip = parsed.client
          url, err = split(parsed.request, " ")
          if err == null {
              .metadata.request.method = url[0]
              .metadata.request.path = url[1]
              .metadata.request.protocol = url[2]
          }
      }
      if err != null {
        abort
      }
  auth_logs:
    type: remap
    inputs:
      - router.auth
    source: |-
      parsed, err = parse_json(.event_message)
      if err == null {
          .metadata.timestamp = parsed.time
          .metadata = merge!(.metadata, parsed)
      }
  rest_logs:
    type: remap
    inputs:
      - router.rest
    source: |-
      parsed, err = parse_regex(.event_message, r'^(?P<time>.*): (?P<msg>.*)$')
      if err == null {
          .event_message = parsed.msg
          .timestamp = to_timestamp!(parsed.time)
          .metadata.host = .project
      }
  realtime_logs_filtered:
    type: filter
    inputs:
      - router.realtime
    condition: '!contains(string!(.event_message), "/health")'
  realtime_logs:
    type: remap
    inputs:
      - realtime_logs_filtered
    source: |-
      .metadata.project = del(.project)
      .metadata.external_id = .metadata.project
      parsed, err = parse_regex(.event_message, r'^(?P<time>\\d+:\\d+:\\d+\\.\\d+) \\[(?P<level>\\w+)\\] (?P<msg>.*)$')
      if err == null {
          .event_message = parsed.msg
          .metadata.level = parsed.level
      }
  functions_logs:
    type: remap
    inputs:
      - router.functions
    source: |-
      .metadata.project_ref = del(.project)
  storage_logs:
    type: remap
    inputs:
      - router.storage
    source: |-
      .metadata.project = del(.project)
      .metadata.tenantId = .metadata.project
      parsed, err = parse_json(.event_message)
      if err == null {
          .event_message = parsed.msg
          .metadata.level = parsed.level
          .metadata.timestamp = parsed.time
          .metadata.context[0].host = parsed.hostname
          .metadata.context[0].pid = parsed.pid
      }
  db_logs:
    type: remap
    inputs:
      - router.db
    source: |-
      .metadata.host = "db-default"
      .metadata.parsed.timestamp = .timestamp

      parsed, err = parse_regex(.event_message, r'.*(?P<level>INFO|NOTICE|WARNING|ERROR|LOG|FATAL|PANIC?):.*', numeric_groups: true)

      if err != null || parsed == null {
        .metadata.parsed.error_severity = "info"
      }
      if parsed.level != null {
       .metadata.parsed.error_severity = parsed.level
      }
      if .metadata.parsed.error_severity == "info" {
          .metadata.parsed.error_severity = "log"
      }
      .metadata.parsed.error_severity = upcase!(.metadata.parsed.error_severity)

sinks:
  logflare_auth:
    type: 'http'
    inputs:
      - auth_logs
    encoding:
      codec: 'json'
    method: 'post'
    request:
      retry_max_duration_secs: 30
      retry_initial_backoff_secs: 1
      headers:
        x-api-key: \${LOGFLARE_PUBLIC_ACCESS_TOKEN?LOGFLARE_PUBLIC_ACCESS_TOKEN is required}
    uri: 'http://analytics:4000/api/logs?source_name=gotrue.logs.prod'
  logflare_realtime:
    type: 'http'
    inputs:
      - realtime_logs
    encoding:
      codec: 'json'
    method: 'post'
    request:
      retry_max_duration_secs: 30
      retry_initial_backoff_secs: 1
      headers:
        x-api-key: \${LOGFLARE_PUBLIC_ACCESS_TOKEN?LOGFLARE_PUBLIC_ACCESS_TOKEN is required}
    uri: 'http://analytics:4000/api/logs?source_name=realtime.logs.prod'
  logflare_rest:
    type: 'http'
    inputs:
      - rest_logs
    encoding:
      codec: 'json'
    method: 'post'
    request:
      retry_max_duration_secs: 30
      retry_initial_backoff_secs: 1
      headers:
        x-api-key: \${LOGFLARE_PUBLIC_ACCESS_TOKEN?LOGFLARE_PUBLIC_ACCESS_TOKEN is required}
    uri: 'http://analytics:4000/api/logs?source_name=postgREST.logs.prod'
  logflare_db:
    type: 'http'
    inputs:
      - db_logs
    encoding:
      codec: 'json'
    method: 'post'
    request:
      retry_max_duration_secs: 30
      retry_initial_backoff_secs: 1
      headers:
        x-api-key: \${LOGFLARE_PUBLIC_ACCESS_TOKEN?LOGFLARE_PUBLIC_ACCESS_TOKEN is required}
    uri: 'http://analytics:4000/api/logs?source_name=postgres.logs'
  logflare_functions:
    type: 'http'
    inputs:
      - functions_logs
    encoding:
      codec: 'json'
    method: 'post'
    request:
      retry_max_duration_secs: 30
      retry_initial_backoff_secs: 1
      headers:
        x-api-key: \${LOGFLARE_PUBLIC_ACCESS_TOKEN?LOGFLARE_PUBLIC_ACCESS_TOKEN is required}
    uri: 'http://analytics:4000/api/logs?source_name=deno-relay-logs'
  logflare_storage:
    type: 'http'
    inputs:
      - storage_logs
    encoding:
      codec: 'json'
    method: 'post'
    request:
      retry_max_duration_secs: 30
      retry_initial_backoff_secs: 1
      headers:
        x-api-key: \${LOGFLARE_PUBLIC_ACCESS_TOKEN?LOGFLARE_PUBLIC_ACCESS_TOKEN is required}
    uri: 'http://analytics:4000/api/logs?source_name=storage.logs.prod.2'
  logflare_kong:
    type: 'http'
    inputs:
      - kong_logs
      - kong_err
    encoding:
      codec: 'json'
    method: 'post'
    request:
      retry_max_duration_secs: 30
      retry_initial_backoff_secs: 1
      headers:
        x-api-key: \${LOGFLARE_PUBLIC_ACCESS_TOKEN?LOGFLARE_PUBLIC_ACCESS_TOKEN is required}
    uri: 'http://analytics:4000/api/logs?source_name=cloudflare.logs.prod'
`;
}

function getPoolerExs() {
  return `{:ok, _} = Application.ensure_all_started(:supavisor)

{:ok, version} =
  case Supavisor.Repo.query!("select version()") do
    %{rows: [[ver]]} -> Supavisor.Helpers.parse_pg_version(ver)
    _ -> nil
  end

params = %{
  "external_id" => System.get_env("POOLER_TENANT_ID"),
  "db_host" => "db",
  "db_port" => System.get_env("POSTGRES_PORT"),
  "db_database" => System.get_env("POSTGRES_DB"),
  "require_user" => false,
  "auth_query" => "SELECT * FROM pgbouncer.get_auth($1)",
  "default_max_clients" => System.get_env("POOLER_MAX_CLIENT_CONN"),
  "default_pool_size" => System.get_env("POOLER_DEFAULT_POOL_SIZE"),
  "default_parameter_status" => %{"server_version" => version},
  "users" => [%{
    "db_user" => "pgbouncer",
    "db_password" => System.get_env("POSTGRES_PASSWORD"),
    "mode_type" => System.get_env("POOLER_POOL_MODE"),
    "pool_size" => System.get_env("POOLER_DEFAULT_POOL_SIZE"),
    "is_manager" => true
  }]
}

if !Supavisor.Tenants.get_tenant_by_external_id(params["external_id"]) do
  {:ok, _} = Supavisor.Tenants.create_tenant(params)
end
`;
}

function getFunctionsMainIndex() {
  return `import * as jose from 'https://deno.land/x/jose@v4.14.4/index.ts'

console.log('main function started')

const JWT_SECRET = Deno.env.get('JWT_SECRET')
const VERIFY_JWT = Deno.env.get('VERIFY_JWT') === 'true'

function getAuthToken(req: Request) {
  const authHeader = req.headers.get('authorization')
  if (!authHeader) {
    throw new Error('Missing authorization header')
  }
  const [bearer, token] = authHeader.split(' ')
  if (bearer !== 'Bearer') {
    throw new Error(\`Auth header is not 'Bearer {token}'\`)
  }
  return token
}

async function verifyJWT(jwt: string): Promise<boolean> {
  const encoder = new TextEncoder()
  const secretKey = encoder.encode(JWT_SECRET)
  try {
    await jose.jwtVerify(jwt, secretKey)
  } catch (err) {
    console.error(err)
    return false
  }
  return true
}

Deno.serve(async (req: Request) => {
  if (req.method !== 'OPTIONS' && VERIFY_JWT) {
    try {
      const token = getAuthToken(req)
      const isValidJWT = await verifyJWT(token)

      if (!isValidJWT) {
        return new Response(JSON.stringify({ msg: 'Invalid JWT' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        })
      }
    } catch (e) {
      console.error(e)
      return new Response(JSON.stringify({ msg: e.toString() }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      })
    }
  }

  const url = new URL(req.url)
  const { pathname } = url
  const path_parts = pathname.split('/')
  const service_name = path_parts[1]

  if (!service_name || service_name === '') {
    const error = { msg: 'missing function name in request' }
    return new Response(JSON.stringify(error), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    })
  }

  const servicePath = \`/home/deno/functions/\${service_name}\`
  console.error(\`serving the request with \${servicePath}\`)

  const memoryLimitMb = 150
  const workerTimeoutMs = 1 * 60 * 1000
  const noModuleCache = false
  const importMapPath = null
  const envVarsObj = Deno.env.toObject()
  const envVars = Object.keys(envVarsObj).map((k) => [k, envVarsObj[k]])

  try {
    const worker = await EdgeRuntime.userWorkers.create({
      servicePath,
      memoryLimitMb,
      workerTimeoutMs,
      noModuleCache,
      importMapPath,
      envVars,
    })
    return await worker.fetch(req)
  } catch (e) {
    const error = { msg: e.toString() }
    return new Response(JSON.stringify(error), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    })
  }
})
`;
}

function getFunctionsHelloIndex() {
  return `Deno.serve(async () => {
  return new Response(
    \`"Hello from Edge Functions!"\`,
    { headers: { "Content-Type": "application/json" } },
  )
})
`;
}

function getSupabaseSql() {
  return `\\set pguser \`echo "$POSTGRES_USER"\`

CREATE DATABASE _supabase WITH OWNER :pguser;
`;
}

function getRealtimeSql() {
  return `\\set pguser \`echo "$POSTGRES_USER"\`

create schema if not exists _realtime;
alter schema _realtime owner to :pguser;
`;
}

function getRolesSql() {
  return `-- NOTE: change to your own passwords for production environments
\\set pgpass \`echo "$POSTGRES_PASSWORD"\`

ALTER USER authenticator WITH PASSWORD :'pgpass';
ALTER USER pgbouncer WITH PASSWORD :'pgpass';
ALTER USER supabase_auth_admin WITH PASSWORD :'pgpass';
ALTER USER supabase_functions_admin WITH PASSWORD :'pgpass';
ALTER USER supabase_storage_admin WITH PASSWORD :'pgpass';
`;
}

function getWebhooksSql() {
  return `BEGIN;
  -- Create pg_net extension
  CREATE EXTENSION IF NOT EXISTS pg_net SCHEMA extensions;
  -- Create supabase_functions schema
  CREATE SCHEMA supabase_functions AUTHORIZATION supabase_admin;
  GRANT USAGE ON SCHEMA supabase_functions TO postgres, anon, authenticated, service_role;
  ALTER DEFAULT PRIVILEGES IN SCHEMA supabase_functions GRANT ALL ON TABLES TO postgres, anon, authenticated, service_role;
  ALTER DEFAULT PRIVILEGES IN SCHEMA supabase_functions GRANT ALL ON FUNCTIONS TO postgres, anon, authenticated, service_role;
  ALTER DEFAULT PRIVILEGES IN SCHEMA supabase_functions GRANT ALL ON SEQUENCES TO postgres, anon, authenticated, service_role;
  -- supabase_functions.migrations definition
  CREATE TABLE supabase_functions.migrations (
    version text PRIMARY KEY,
    inserted_at timestamptz NOT NULL DEFAULT NOW()
  );
  -- Initial supabase_functions migration
  INSERT INTO supabase_functions.migrations (version) VALUES ('initial');
  -- supabase_functions.hooks definition
  CREATE TABLE supabase_functions.hooks (
    id bigserial PRIMARY KEY,
    hook_table_id integer NOT NULL,
    hook_name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    request_id bigint
  );
  CREATE INDEX supabase_functions_hooks_request_id_idx ON supabase_functions.hooks USING btree (request_id);
  CREATE INDEX supabase_functions_hooks_h_table_id_h_name_idx ON supabase_functions.hooks USING btree (hook_table_id, hook_name);
  COMMENT ON TABLE supabase_functions.hooks IS 'Supabase Functions Hooks: Audit trail for triggered hooks.';
  CREATE FUNCTION supabase_functions.http_request()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $function$
    DECLARE
      request_id bigint;
      payload jsonb;
      url text := TG_ARGV[0]::text;
      method text := TG_ARGV[1]::text;
      headers jsonb DEFAULT '{}'::jsonb;
      params jsonb DEFAULT '{}'::jsonb;
      timeout_ms integer DEFAULT 1000;
    BEGIN
      IF url IS NULL OR url = 'null' THEN
        RAISE EXCEPTION 'url argument is missing';
      END IF;

      IF method IS NULL OR method = 'null' THEN
        RAISE EXCEPTION 'method argument is missing';
      END IF;

      IF TG_ARGV[2] IS NULL OR TG_ARGV[2] = 'null' THEN
        headers = '{"Content-Type": "application/json"}'::jsonb;
      ELSE
        headers = TG_ARGV[2]::jsonb;
      END IF;

      IF TG_ARGV[3] IS NULL OR TG_ARGV[3] = 'null' THEN
        params = '{}'::jsonb;
      ELSE
        params = TG_ARGV[3]::jsonb;
      END IF;

      IF TG_ARGV[4] IS NULL OR TG_ARGV[4] = 'null' THEN
        timeout_ms = 1000;
      ELSE
        timeout_ms = TG_ARGV[4]::integer;
      END IF;

      CASE
        WHEN method = 'GET' THEN
          SELECT http_get INTO request_id FROM net.http_get(
            url,
            params,
            headers,
            timeout_ms
          );
        WHEN method = 'POST' THEN
          payload = jsonb_build_object(
            'old_record', OLD,
            'record', NEW,
            'type', TG_OP,
            'table', TG_TABLE_NAME,
            'schema', TG_TABLE_SCHEMA
          );

          SELECT http_post INTO request_id FROM net.http_post(
            url,
            payload,
            params,
            headers,
            timeout_ms
          );
        ELSE
          RAISE EXCEPTION 'method argument % is invalid', method;
      END CASE;

      INSERT INTO supabase_functions.hooks
        (hook_table_id, hook_name, request_id)
      VALUES
        (TG_RELID, TG_NAME, request_id);

      RETURN NEW;
    END
  $function$;
  -- Supabase super admin
  DO
  $$
  BEGIN
    IF NOT EXISTS (
      SELECT 1
      FROM pg_roles
      WHERE rolname = 'supabase_functions_admin'
    )
    THEN
      CREATE USER supabase_functions_admin NOINHERIT CREATEROLE LOGIN NOREPLICATION;
    END IF;
  END
  $$;
  GRANT ALL PRIVILEGES ON SCHEMA supabase_functions TO supabase_functions_admin;
  GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA supabase_functions TO supabase_functions_admin;
  GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA supabase_functions TO supabase_functions_admin;
  ALTER USER supabase_functions_admin SET search_path = "supabase_functions";
  ALTER table "supabase_functions".migrations OWNER TO supabase_functions_admin;
  ALTER table "supabase_functions".hooks OWNER TO supabase_functions_admin;
  ALTER function "supabase_functions".http_request() OWNER TO supabase_functions_admin;
  GRANT supabase_functions_admin TO postgres;
  -- Remove unused supabase_pg_net_admin role
  DO
  $$
  BEGIN
    IF EXISTS (
      SELECT 1
      FROM pg_roles
      WHERE rolname = 'supabase_pg_net_admin'
    )
    THEN
      REASSIGN OWNED BY supabase_pg_net_admin TO supabase_admin;
      DROP OWNED BY supabase_pg_net_admin;
      DROP ROLE supabase_pg_net_admin;
    END IF;
  END
  $$;
  -- pg_net grants when extension is already enabled
  DO
  $$
  BEGIN
    IF EXISTS (
      SELECT 1
      FROM pg_extension
      WHERE extname = 'pg_net'
    )
    THEN
      GRANT USAGE ON SCHEMA net TO supabase_functions_admin, postgres, anon, authenticated, service_role;
      ALTER function net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) SECURITY DEFINER;
      ALTER function net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) SECURITY DEFINER;
      ALTER function net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) SET search_path = net;
      ALTER function net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) SET search_path = net;
      REVOKE ALL ON FUNCTION net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) FROM PUBLIC;
      REVOKE ALL ON FUNCTION net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) FROM PUBLIC;
      GRANT EXECUTE ON FUNCTION net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) TO supabase_functions_admin, postgres, anon, authenticated, service_role;
      GRANT EXECUTE ON FUNCTION net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) TO supabase_functions_admin, postgres, anon, authenticated, service_role;
    END IF;
  END
  $$;
  -- Event trigger for pg_net
  CREATE OR REPLACE FUNCTION extensions.grant_pg_net_access()
  RETURNS event_trigger
  LANGUAGE plpgsql
  AS $$
  BEGIN
    IF EXISTS (
      SELECT 1
      FROM pg_event_trigger_ddl_commands() AS ev
      JOIN pg_extension AS ext
      ON ev.objid = ext.oid
      WHERE ext.extname = 'pg_net'
    )
    THEN
      GRANT USAGE ON SCHEMA net TO supabase_functions_admin, postgres, anon, authenticated, service_role;
      ALTER function net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) SECURITY DEFINER;
      ALTER function net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) SECURITY DEFINER;
      ALTER function net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) SET search_path = net;
      ALTER function net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) SET search_path = net;
      REVOKE ALL ON FUNCTION net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) FROM PUBLIC;
      REVOKE ALL ON FUNCTION net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) FROM PUBLIC;
      GRANT EXECUTE ON FUNCTION net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) TO supabase_functions_admin, postgres, anon, authenticated, service_role;
      GRANT EXECUTE ON FUNCTION net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) TO supabase_functions_admin, postgres, anon, authenticated, service_role;
    END IF;
  END;
  $$;
  COMMENT ON FUNCTION extensions.grant_pg_net_access IS 'Grants access to pg_net';
  DO
  $$
  BEGIN
    IF NOT EXISTS (
      SELECT 1
      FROM pg_event_trigger
      WHERE evtname = 'issue_pg_net_access'
    ) THEN
      CREATE EVENT TRIGGER issue_pg_net_access ON ddl_command_end WHEN TAG IN ('CREATE EXTENSION')
      EXECUTE PROCEDURE extensions.grant_pg_net_access();
    END IF;
  END
  $$;
  INSERT INTO supabase_functions.migrations (version) VALUES ('20210809183423_update_grants');
  ALTER function supabase_functions.http_request() SECURITY DEFINER;
  ALTER function supabase_functions.http_request() SET search_path = supabase_functions;
  REVOKE ALL ON FUNCTION supabase_functions.http_request() FROM PUBLIC;
  GRANT EXECUTE ON FUNCTION supabase_functions.http_request() TO postgres, anon, authenticated, service_role;
COMMIT;
`;
}

function getJwtSql() {
  return `\\set jwt_secret \`echo "$JWT_SECRET"\`
\\set jwt_exp \`echo "$JWT_EXP"\`

ALTER DATABASE postgres SET "app.settings.jwt_secret" TO :'jwt_secret';
ALTER DATABASE postgres SET "app.settings.jwt_exp" TO :'jwt_exp';
`;
}

function getLogsSql() {
  return `\\set pguser \`echo "$POSTGRES_USER"\`

\\c _supabase
create schema if not exists _analytics;
alter schema _analytics owner to :pguser;
\\c postgres
`;
}

function getPoolerSql() {
  return `\\set pguser \`echo "$POSTGRES_USER"\`

\\c _supabase
create schema if not exists _supavisor;
alter schema _supavisor owner to :pguser;
\\c postgres
`;
}

function getSchemaAutheliaSh() {
  return `#!/bin/bash
set -e
psql -v ON_ERROR_STOP=1 -U postgres -d "$POSTGRES_DB" -c "CREATE SCHEMA IF NOT EXISTS \\"$AUTHELIA_SCHEMA\\""
`;
}

// ── Dynamic config builders ─────────────────────────────────────────────────

export function generateEnvFile(config, secrets) {
  const {
    domain, serverName, supabaseEmail,
    smtpHost, smtpPort, smtpUser, smtpPass, smtpSenderName, smtpAdminEmail,
    siteUrl, additionalRedirectUrls,
  } = config;
  return `############
# Secrets
############
POSTGRES_PASSWORD=${secrets.postgresPassword}
JWT_SECRET=${secrets.jwtSecret}
ANON_KEY=${secrets.anonKey}
SERVICE_ROLE_KEY=${secrets.serviceRoleKey}
DASHBOARD_USERNAME=supabase
SECRET_KEY_BASE=${secrets.secretKeyBase}
VAULT_ENC_KEY=${secrets.vaultEncKey}
PG_META_CRYPTO_KEY=${secrets.pgMetaCryptoKey}
RESTIC_PASSWORD=${secrets.resticPassword}

############
# Database
############
POSTGRES_HOST=db
POSTGRES_DB=postgres
POSTGRES_PORT=5432

############
# Supavisor
############
POOLER_PROXY_PORT_TRANSACTION=6543
POOLER_DEFAULT_POOL_SIZE=20
POOLER_MAX_CLIENT_CONN=100
POOLER_TENANT_ID=${config.serverName}
POOLER_DB_POOL_SIZE=5

############
# API Proxy
############
KONG_HTTP_PORT=8000
KONG_HTTPS_PORT=8443

############
# API
############
PGRST_DB_SCHEMAS=public,storage,graphql_public

############
# Auth
############
SITE_URL=${siteUrl || domain}
ADDITIONAL_REDIRECT_URLS=${additionalRedirectUrls || ''}
JWT_EXPIRY=3600
DISABLE_SIGNUP=false
API_EXTERNAL_URL=${domain}/goapi

## Mailer Config
MAILER_URLPATHS_CONFIRMATION="/auth/v1/verify"
MAILER_URLPATHS_INVITE="/auth/v1/verify"
MAILER_URLPATHS_RECOVERY="/auth/v1/verify"
MAILER_URLPATHS_EMAIL_CHANGE="/auth/v1/verify"

## Email auth
ENABLE_EMAIL_SIGNUP=true
ENABLE_EMAIL_AUTOCONFIRM=${smtpHost ? 'false' : 'true'}
SMTP_ADMIN_EMAIL=${smtpAdminEmail || supabaseEmail}
SMTP_HOST=${smtpHost || ''}
SMTP_PORT=${smtpPort || '587'}
SMTP_USER=${smtpUser || ''}
SMTP_PASS=${smtpPass || ''}
SMTP_SENDER_NAME=${smtpSenderName || serverName}
ENABLE_ANONYMOUS_USERS=false

## Phone auth
ENABLE_PHONE_SIGNUP=true
ENABLE_PHONE_AUTOCONFIRM=true

############
# Studio
############
STUDIO_DEFAULT_ORGANIZATION=Default Organization
STUDIO_DEFAULT_PROJECT=Default Project
SUPABASE_PUBLIC_URL=${domain}
IMGPROXY_ENABLE_WEBP_DETECTION=true
OPENAI_API_KEY=

############
# Functions
############
FUNCTIONS_VERIFY_JWT=false

############
# Logs
############
LOGFLARE_PUBLIC_ACCESS_TOKEN=${secrets.logflarePublicToken}
LOGFLARE_PRIVATE_ACCESS_TOKEN=${secrets.logflarePrivateToken}
DOCKER_SOCKET_LOCATION=/var/run/docker.sock
GOOGLE_PROJECT_ID=GOOGLE_PROJECT_ID
GOOGLE_PROJECT_NUMBER=GOOGLE_PROJECT_NUMBER

############
# Storage
############
STORAGE_TENANT_ID=stub
GLOBAL_S3_BUCKET=stub
REGION=stub
S3_PROTOCOL_ACCESS_KEY_ID=${secrets.s3AccessKeyId}
S3_PROTOCOL_ACCESS_KEY_SECRET=${secrets.s3AccessKeySecret}
MINIO_ROOT_USER=supa-storage
MINIO_ROOT_PASSWORD=${secrets.minioRootPassword}

############
# Server
############
SERVER_NAME=${config.serverName}

############
# Backups (S3)
############
RESTIC_REPOSITORY=s3:s3.${config.s3Region}.amazonaws.com/${config.s3Bucket}/${config.serverName}
AWS_ACCESS_KEY_ID=${config.s3AccessKey}
AWS_SECRET_ACCESS_KEY=${config.s3SecretKey}
`;
}

export function generateDockerCompose(config) {
  const { enableAuthelia, enableRedis } = config;

  // All Docker Compose ${VAR} references are escaped as \${VAR} in JS template literals
  let compose = `name: supabase

services:
  supabase-studio:
    container_name: supabase-studio
    image: supabase/studio:2026.01.27-sha-6aa59ff
    restart: unless-stopped
    healthcheck:
      test:
        [
          "CMD",
          "node",
          "-e",
          "fetch('http://supabase-studio:3000/api/platform/profile').then((r) => {if (r.status !== 200) throw new Error(r.status)})"
        ]
      timeout: 10s
      interval: 5s
      retries: 3
    depends_on:
      analytics:
        condition: service_healthy
    environment:
      HOSTNAME: "::"
      STUDIO_PG_META_URL: http://meta:8080
      POSTGRES_PORT: \${POSTGRES_PORT}
      POSTGRES_HOST: \${POSTGRES_HOST}
      POSTGRES_DB: \${POSTGRES_DB}
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD}
      POSTGRES_USER_READ_WRITE: postgres
      PG_META_CRYPTO_KEY: \${PG_META_CRYPTO_KEY}
      DEFAULT_ORGANIZATION_NAME: \${STUDIO_DEFAULT_ORGANIZATION}
      DEFAULT_PROJECT_NAME: \${STUDIO_DEFAULT_PROJECT}
      OPENAI_API_KEY: \${OPENAI_API_KEY:-}
      SUPABASE_URL: http://kong:8000
      SUPABASE_PUBLIC_URL: \${SUPABASE_PUBLIC_URL}
      SUPABASE_ANON_KEY: \${ANON_KEY}
      SUPABASE_SERVICE_KEY: \${SERVICE_ROLE_KEY}
      AUTH_JWT_SECRET: \${JWT_SECRET}
      LOGFLARE_API_KEY: \${LOGFLARE_PUBLIC_ACCESS_TOKEN}
      LOGFLARE_PUBLIC_ACCESS_TOKEN: \${LOGFLARE_PUBLIC_ACCESS_TOKEN}
      LOGFLARE_PRIVATE_ACCESS_TOKEN: \${LOGFLARE_PRIVATE_ACCESS_TOKEN}
      LOGFLARE_URL: http://analytics:4000
      NEXT_PUBLIC_ENABLE_LOGS: true
      NEXT_ANALYTICS_BACKEND_PROVIDER: postgres
      SNIPPETS_MANAGEMENT_FOLDER: /app/snippets
      EDGE_FUNCTIONS_MANAGEMENT_FOLDER: /app/edge-functions
    volumes:
      - ./volumes/snippets:/app/snippets:Z
      - ./volumes/functions:/app/edge-functions:Z

  kong:
    container_name: supabase-kong
    image: kong:2.8.1
    restart: unless-stopped
    volumes:
      - ./volumes/api/kong.yml:/home/kong/kong.yml:ro,z
    depends_on:
      analytics:
        condition: service_healthy
    environment:
      KONG_DATABASE: "off"
      KONG_DECLARATIVE_CONFIG: /home/kong/kong.yml
      KONG_DNS_ORDER: LAST,A,CNAME
      KONG_PLUGINS: request-transformer,cors,key-auth,acl,basic-auth,request-termination,ip-restriction
      KONG_NGINX_PROXY_PROXY_BUFFER_SIZE: 160k
      KONG_NGINX_PROXY_PROXY_BUFFERS: 64 160k

  auth:
    container_name: supabase-auth
    image: supabase/gotrue:v2.185.0
    restart: unless-stopped
    healthcheck:
      test:
        [
          "CMD",
          "wget",
          "--no-verbose",
          "--tries=1",
          "--spider",
          "http://localhost:9999/health"
        ]
      timeout: 5s
      interval: 5s
      retries: 3
    depends_on:
      db:
        condition: service_healthy
      analytics:
        condition: service_healthy
    environment:
      GOTRUE_API_HOST: 0.0.0.0
      GOTRUE_API_PORT: 9999
      API_EXTERNAL_URL: \${API_EXTERNAL_URL}
      GOTRUE_DB_DRIVER: postgres
      GOTRUE_DB_DATABASE_URL: postgres://supabase_auth_admin:\${POSTGRES_PASSWORD}@\${POSTGRES_HOST}:\${POSTGRES_PORT}/\${POSTGRES_DB}
      GOTRUE_SITE_URL: \${SITE_URL}
      GOTRUE_URI_ALLOW_LIST: \${ADDITIONAL_REDIRECT_URLS}
      GOTRUE_DISABLE_SIGNUP: \${DISABLE_SIGNUP}
      GOTRUE_JWT_ADMIN_ROLES: service_role
      GOTRUE_JWT_AUD: authenticated
      GOTRUE_JWT_DEFAULT_GROUP_NAME: authenticated
      GOTRUE_JWT_EXP: \${JWT_EXPIRY}
      GOTRUE_JWT_SECRET: \${JWT_SECRET}
      GOTRUE_EXTERNAL_EMAIL_ENABLED: \${ENABLE_EMAIL_SIGNUP}
      GOTRUE_EXTERNAL_ANONYMOUS_USERS_ENABLED: \${ENABLE_ANONYMOUS_USERS}
      GOTRUE_MAILER_AUTOCONFIRM: \${ENABLE_EMAIL_AUTOCONFIRM}
      GOTRUE_SMTP_ADMIN_EMAIL: \${SMTP_ADMIN_EMAIL}
      GOTRUE_SMTP_HOST: \${SMTP_HOST}
      GOTRUE_SMTP_PORT: \${SMTP_PORT}
      GOTRUE_SMTP_USER: \${SMTP_USER}
      GOTRUE_SMTP_PASS: \${SMTP_PASS}
      GOTRUE_SMTP_SENDER_NAME: \${SMTP_SENDER_NAME}
      GOTRUE_MAILER_URLPATHS_INVITE: \${MAILER_URLPATHS_INVITE}
      GOTRUE_MAILER_URLPATHS_CONFIRMATION: \${MAILER_URLPATHS_CONFIRMATION}
      GOTRUE_MAILER_URLPATHS_RECOVERY: \${MAILER_URLPATHS_RECOVERY}
      GOTRUE_MAILER_URLPATHS_EMAIL_CHANGE: \${MAILER_URLPATHS_EMAIL_CHANGE}
      GOTRUE_EXTERNAL_PHONE_ENABLED: \${ENABLE_PHONE_SIGNUP}
      GOTRUE_SMS_AUTOCONFIRM: \${ENABLE_PHONE_AUTOCONFIRM}

  rest:
    container_name: supabase-rest
    image: postgrest/postgrest:v14.3
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
      analytics:
        condition: service_healthy
    environment:
      PGRST_DB_URI: postgres://authenticator:\${POSTGRES_PASSWORD}@\${POSTGRES_HOST}:\${POSTGRES_PORT}/\${POSTGRES_DB}
      PGRST_DB_SCHEMAS: \${PGRST_DB_SCHEMAS}
      PGRST_DB_ANON_ROLE: anon
      PGRST_JWT_SECRET: \${JWT_SECRET}
      PGRST_DB_USE_LEGACY_GUCS: "false"
      PGRST_APP_SETTINGS_JWT_SECRET: \${JWT_SECRET}
      PGRST_APP_SETTINGS_JWT_EXP: \${JWT_EXPIRY}
    command: "postgrest"

  realtime:
    container_name: realtime-dev.supabase-realtime
    image: supabase/realtime:v2.72.0
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
      analytics:
        condition: service_healthy
    healthcheck:
      test:
        [
          "CMD-SHELL",
          'curl -sSfL --head -o /dev/null -H "Authorization: Bearer \${ANON_KEY}" http://localhost:4000/api/tenants/realtime-dev/health'
        ]
      timeout: 5s
      interval: 30s
      retries: 3
      start_period: 10s
    environment:
      PORT: 4000
      DB_HOST: \${POSTGRES_HOST}
      DB_PORT: \${POSTGRES_PORT}
      DB_USER: supabase_admin
      DB_PASSWORD: \${POSTGRES_PASSWORD}
      DB_NAME: \${POSTGRES_DB}
      DB_AFTER_CONNECT_QUERY: "SET search_path TO _realtime"
      DB_ENC_KEY: supabaserealtime
      API_JWT_SECRET: \${JWT_SECRET}
      SECRET_KEY_BASE: \${SECRET_KEY_BASE}
      ERL_AFLAGS: -proto_dist inet_tcp
      DNS_NODES: "''"
      RLIMIT_NOFILE: "10000"
      APP_NAME: realtime
      SEED_SELF_HOST: "true"
      RUN_JANITOR: "true"
      DISABLE_HEALTHCHECK_LOGGING: "true"

  storage:
    container_name: supabase-storage
    image: supabase/storage-api:v1.37.1
    restart: unless-stopped
    volumes:
      - ./volumes/storage:/var/lib/storage:z
    healthcheck:
      test:
        [
          "CMD",
          "wget",
          "--no-verbose",
          "--tries=1",
          "--spider",
          "http://storage:5000/status"
        ]
      timeout: 5s
      interval: 5s
      retries: 3
    depends_on:
      db:
        condition: service_healthy
      rest:
        condition: service_started
      imgproxy:
        condition: service_started
    environment:
      ANON_KEY: \${ANON_KEY}
      SERVICE_KEY: \${SERVICE_ROLE_KEY}
      POSTGREST_URL: http://rest:3000
      PGRST_JWT_SECRET: \${JWT_SECRET}
      DATABASE_URL: postgres://supabase_storage_admin:\${POSTGRES_PASSWORD}@\${POSTGRES_HOST}:\${POSTGRES_PORT}/\${POSTGRES_DB}
      REQUEST_ALLOW_X_FORWARDED_PATH: "true"
      FILE_SIZE_LIMIT: 52428800
      STORAGE_BACKEND: file
      FILE_STORAGE_BACKEND_PATH: /var/lib/storage
      TENANT_ID: \${STORAGE_TENANT_ID}
      REGION: \${REGION}
      GLOBAL_S3_BUCKET: \${GLOBAL_S3_BUCKET}
      ENABLE_IMAGE_TRANSFORMATION: "true"
      IMGPROXY_URL: http://imgproxy:5001
      S3_PROTOCOL_ACCESS_KEY_ID: \${S3_PROTOCOL_ACCESS_KEY_ID}
      S3_PROTOCOL_ACCESS_KEY_SECRET: \${S3_PROTOCOL_ACCESS_KEY_SECRET}

  imgproxy:
    container_name: supabase-imgproxy
    image: darthsim/imgproxy:v3.30.1
    restart: unless-stopped
    volumes:
      - ./volumes/storage:/var/lib/storage:z
    healthcheck:
      test: ["CMD", "imgproxy", "health"]
      timeout: 5s
      interval: 5s
      retries: 3
    environment:
      IMGPROXY_BIND: ":5001"
      IMGPROXY_LOCAL_FILESYSTEM_ROOT: /
      IMGPROXY_USE_ETAG: "true"
      IMGPROXY_ENABLE_WEBP_DETECTION: \${IMGPROXY_ENABLE_WEBP_DETECTION}
      IMGPROXY_MAX_SRC_RESOLUTION: 16.8

  meta:
    container_name: supabase-meta
    image: supabase/postgres-meta:v0.95.2
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
      analytics:
        condition: service_healthy
    environment:
      PG_META_PORT: 8080
      PG_META_DB_HOST: \${POSTGRES_HOST}
      PG_META_DB_PORT: \${POSTGRES_PORT}
      PG_META_DB_NAME: \${POSTGRES_DB}
      PG_META_DB_USER: postgres
      PG_META_DB_PASSWORD: \${POSTGRES_PASSWORD}
      CRYPTO_KEY: \${PG_META_CRYPTO_KEY}

  functions:
    container_name: supabase-edge-functions
    image: supabase/edge-runtime:v1.70.0
    restart: unless-stopped
    volumes:
      - ./volumes/functions:/home/deno/functions:Z
      - deno_cache:/root/.cache/deno
    depends_on:
      analytics:
        condition: service_healthy
    environment:
      JWT_SECRET: \${JWT_SECRET}
      SUPABASE_URL: http://kong:8000
      SUPABASE_ANON_KEY: \${ANON_KEY}
      SUPABASE_SERVICE_ROLE_KEY: \${SERVICE_ROLE_KEY}
      SUPABASE_DB_URL: postgresql://postgres:\${POSTGRES_PASSWORD}@\${POSTGRES_HOST}:\${POSTGRES_PORT}/\${POSTGRES_DB}
      VERIFY_JWT: "\${FUNCTIONS_VERIFY_JWT}"
    command: ["start", "--main-service", "/home/deno/functions/main"]

  analytics:
    container_name: supabase-analytics
    image: supabase/logflare:1.30.3
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "http://localhost:4000/health"]
      timeout: 5s
      interval: 5s
      retries: 10
    depends_on:
      db:
        condition: service_healthy
    environment:
      LOGFLARE_NODE_HOST: 127.0.0.1
      DB_USERNAME: supabase_admin
      DB_DATABASE: _supabase
      DB_HOSTNAME: \${POSTGRES_HOST}
      DB_PORT: \${POSTGRES_PORT}
      DB_PASSWORD: \${POSTGRES_PASSWORD}
      DB_SCHEMA: _analytics
      LOGFLARE_PUBLIC_ACCESS_TOKEN: \${LOGFLARE_PUBLIC_ACCESS_TOKEN}
      LOGFLARE_PRIVATE_ACCESS_TOKEN: \${LOGFLARE_PRIVATE_ACCESS_TOKEN}
      LOGFLARE_SINGLE_TENANT: true
      LOGFLARE_SUPABASE_MODE: true
      POSTGRES_BACKEND_URL: postgresql://supabase_admin:\${POSTGRES_PASSWORD}@\${POSTGRES_HOST}:\${POSTGRES_PORT}/_supabase
      POSTGRES_BACKEND_SCHEMA: _analytics
      LOGFLARE_FEATURE_FLAG_OVERRIDE: multibackend=true

  db:
    container_name: supabase-db
    image: supabase/postgres:15.8.1.085
    restart: unless-stopped
    volumes:
      - ./volumes/db/realtime.sql:/docker-entrypoint-initdb.d/migrations/99-realtime.sql:Z
      - ./volumes/db/webhooks.sql:/docker-entrypoint-initdb.d/init-scripts/98-webhooks.sql:Z
      - ./volumes/db/roles.sql:/docker-entrypoint-initdb.d/init-scripts/99-roles.sql:Z
      - ./volumes/db/jwt.sql:/docker-entrypoint-initdb.d/init-scripts/99-jwt.sql:Z
      - ./volumes/db/data:/var/lib/postgresql/data:Z
      - ./volumes/db/_supabase.sql:/docker-entrypoint-initdb.d/migrations/97-_supabase.sql:Z
      - ./volumes/db/logs.sql:/docker-entrypoint-initdb.d/migrations/99-logs.sql:Z
      - ./volumes/db/pooler.sql:/docker-entrypoint-initdb.d/migrations/99-pooler.sql:Z
      - db-config:/etc/postgresql-custom${enableAuthelia ? `
      - ./volumes/db/schema-authelia.sh:/docker-entrypoint-initdb.d/schema-authelia.sh` : ''}
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "postgres", "-h", "localhost"]
      interval: 5s
      timeout: 5s
      retries: 10
    depends_on:
      vector:
        condition: service_healthy
    environment:
      POSTGRES_HOST: /var/run/postgresql
      PGPORT: \${POSTGRES_PORT}
      POSTGRES_PORT: \${POSTGRES_PORT}
      PGPASSWORD: \${POSTGRES_PASSWORD:?error}
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD}
      PGDATABASE: \${POSTGRES_DB}
      POSTGRES_DB: \${POSTGRES_DB}
      JWT_SECRET: \${JWT_SECRET}
      JWT_EXP: \${JWT_EXPIRY}${enableAuthelia ? `
      AUTHELIA_SCHEMA: authelia` : ''}
    command: [
        "postgres",
        "-c",
        "config_file=/etc/postgresql/postgresql.conf",
        "-c",
        "log_min_messages=fatal"
      ]

  vector:
    container_name: supabase-vector
    image: timberio/vector:0.28.1-alpine
    restart: unless-stopped
    volumes:
      - ./volumes/logs/vector.yml:/etc/vector/vector.yml:ro,z
      - \${DOCKER_SOCKET_LOCATION}:/var/run/docker.sock:ro,z
    healthcheck:
      test:
        [
          "CMD",
          "wget",
          "--no-verbose",
          "--tries=1",
          "--spider",
          "http://vector:9001/health"
        ]
      timeout: 5s
      interval: 5s
      retries: 3
    environment:
      LOGFLARE_PUBLIC_ACCESS_TOKEN: \${LOGFLARE_PUBLIC_ACCESS_TOKEN}
    command: ["--config", "/etc/vector/vector.yml"]
    security_opt:
      - "label=disable"

  supavisor:
    container_name: supabase-pooler
    image: supabase/supavisor:2.7.4
    restart: unless-stopped
    ulimits:
      nofile:
        soft: 100000
        hard: 100000
    ports:
      - \${POSTGRES_PORT}:5432
      - \${POOLER_PROXY_PORT_TRANSACTION}:6543
    volumes:
      - ./volumes/pooler/pooler.exs:/etc/pooler/pooler.exs:ro,z
    healthcheck:
      test:
        [
          "CMD",
          "curl",
          "-sSfL",
          "--head",
          "-o",
          "/dev/null",
          "http://127.0.0.1:4000/api/health"
        ]
      interval: 10s
      timeout: 5s
      retries: 5
    depends_on:
      db:
        condition: service_healthy
      analytics:
        condition: service_healthy
    environment:
      PORT: 4000
      POSTGRES_PORT: \${POSTGRES_PORT}
      POSTGRES_DB: \${POSTGRES_DB}
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD}
      DATABASE_URL: ecto://supabase_admin:\${POSTGRES_PASSWORD}@\${POSTGRES_HOST}:\${POSTGRES_PORT}/_supabase
      CLUSTER_POSTGRES: true
      SECRET_KEY_BASE: \${SECRET_KEY_BASE}
      VAULT_ENC_KEY: \${VAULT_ENC_KEY}
      API_JWT_SECRET: \${JWT_SECRET}
      METRICS_JWT_SECRET: \${JWT_SECRET}
      REGION: local
      ERL_AFLAGS: -proto_dist inet_tcp
      POOLER_TENANT_ID: \${POOLER_TENANT_ID}
      POOLER_DEFAULT_POOL_SIZE: \${POOLER_DEFAULT_POOL_SIZE}
      POOLER_MAX_CLIENT_CONN: \${POOLER_MAX_CLIENT_CONN}
      POOLER_POOL_MODE: transaction
      DB_POOL_SIZE: \${POOLER_DB_POOL_SIZE}
    command:
      [
        "/bin/sh",
        "-c",
        '/app/bin/migrate && /app/bin/supavisor eval "$$(cat /etc/pooler/pooler.exs)" && /app/bin/server'
      ]

  caddy:
    container_name: caddy-container
    image: caddy:2.10.2
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    depends_on:
      kong:
        condition: service_healthy${enableAuthelia ? `
      authelia:
        condition: service_healthy` : ''}
    environment:
      DOMAIN: \${SUPABASE_PUBLIC_URL:?error}${!enableAuthelia ? `
      PROXY_AUTH_USERNAME: \${PROXY_AUTH_USERNAME:?error}
      PROXY_AUTH_PASSWORD: \${PROXY_AUTH_PASSWORD:?error}` : ''}
    volumes:
      - ./volumes/caddy/Caddyfile:/etc/caddy/Caddyfile
      - ./volumes/caddy/caddy_data:/data
      - ./volumes/caddy/caddy_config:/config
      - ./volumes/caddy/snippets:/etc/caddy/snippets

  docker-socket-proxy:
    container_name: docker-socket-proxy
    image: tecnativa/docker-socket-proxy:latest
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      LOG_LEVEL: warning
      CONTAINERS: 1
      IMAGES: 1
      POST: 1
      ALLOW_START: 1
      ALLOW_STOP: 1
      ALLOW_RESTARTS: 1
      AUTH: 0
      SECRETS: 0
      EXEC: 0
      NETWORKS: 0
      VOLUMES: 0
      BUILD: 0
      COMMIT: 0
      SWARM: 0
    expose:
      - "2375"
    networks:
      - management-net

  management:
    container_name: supabase-management
    image: ghcr.io/nadercas/supafast:latest
    restart: unless-stopped
    volumes:
      - /var/log:/host-logs:ro
      - ./backup.env:/app/backup.env:ro
      - .:/supabase:ro
    expose:
      - "3001"
    depends_on:
      - docker-socket-proxy
    networks:
      - default
      - management-net
    environment:
      NODE_ENV: production
      DOCKER_HOST: tcp://docker-socket-proxy:2375
      SUPABASE_DIR: /supabase
      SERVER_NAME: \${SERVER_NAME}
      RESTIC_REPOSITORY: \${RESTIC_REPOSITORY}
      RESTIC_PASSWORD: \${RESTIC_PASSWORD}
      AWS_ACCESS_KEY_ID: \${AWS_ACCESS_KEY_ID}
      AWS_SECRET_ACCESS_KEY: \${AWS_SECRET_ACCESS_KEY}`;

  // Conditional: Authelia
  if (enableAuthelia) {
    compose += `

  authelia:
    container_name: authelia
    image: authelia/authelia:4.38
    restart: unless-stopped
    volumes:
      - ./volumes/authelia:/config
    depends_on:
      db:
        condition: service_healthy${enableRedis ? `
      redis:
        condition: service_healthy` : ''}
    expose:
      - 9091
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:9091/api/health"]
      timeout: 5s
      interval: 5s
      retries: 3
    environment:
      AUTHELIA_STORAGE_POSTGRES_ADDRESS: "tcp://db:5432"
      AUTHELIA_STORAGE_POSTGRES_USERNAME: "postgres"
      AUTHELIA_STORAGE_POSTGRES_PASSWORD: \${POSTGRES_PASSWORD}
      AUTHELIA_STORAGE_POSTGRES_DATABASE: \${POSTGRES_DB}
      AUTHELIA_STORAGE_POSTGRES_SCHEMA: "authelia"
      AUTHELIA_SESSION_SECRET: \${AUTHELIA_SESSION_SECRET:?error}
      AUTHELIA_STORAGE_ENCRYPTION_KEY: \${AUTHELIA_STORAGE_ENCRYPTION_KEY:?error}
      AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET: \${AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET:?error}`;
  }

  // Conditional: Redis
  if (enableRedis) {
    compose += `

  redis:
    container_name: redis
    image: redis:8.2.1
    restart: unless-stopped
    expose:
      - 6379
    volumes:
      - ./volumes/redis:/data
    healthcheck:
      test: ["CMD-SHELL", "redis-cli ping | grep PONG"]
      timeout: 5s
      interval: 1s
      retries: 5`;
  }

  compose += `

networks:
  default:
  management-net:
    internal: true

volumes:
  db-config:
  deno_cache:
`;

  return compose;
}

function generateAutheliaConfig(config) {
  const host = config.domain.replace(/^https?:\/\//, '');
  const registeredDomain = host.split('.').slice(-2).join('.');

  return `theme: "auto"
log:
  level: "info"
  format: "json"

server:
  address: "tcp://:9091/authenticate"
  endpoints:
    authz:
      forward-auth:
        implementation: "ForwardAuth"

totp:
  disable: false
  issuer: "${host}"
  period: 30
  skew: 1

identity_validation:
  reset_password:
    jwt_lifespan: "5 minutes"
    jwt_algorithm: "HS256"
    jwt_secret: '{{ env "AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET" }}'

authentication_backend:
  refresh_interval: "5 minutes"
  password_reset:
    disable: false

  file:
    path: "/config/users_database.yml"
    watch: false
    search:
      email: false
      case_insensitive: false
    password:
      algorithm: "bcrypt"
      bcrypt:
        variant: "standard"
        cost: 12

access_control:
  default_policy: "deny"
  rules:
    # Supabase API paths bypass Authelia (handled by Kong key-auth)
    - domain: "${host}"
      policy: "bypass"
      resources:
        - "^/rest/v1(/.*)?$"
        - "^/auth/v1(/.*)?$"
        - "^/realtime/v1(/.*)?$"
        - "^/storage/v1(/.*)?$"
        - "^/functions/v1(/.*)?$"
        - "^/graphql/v1(/.*)?$"
    # Dashboard and Studio require two_factor — enrollment QR shown on first login
    - domain: "${host}"
      policy: "two_factor"

session:
  secret: '{{ env "AUTHELIA_SESSION_SECRET" }}'
  inactivity: "10m"
  expiration: "1h"
  remember_me: "1M"
  cookies:
    - domain: "${registeredDomain}"
      authelia_url: "${config.domain}/authenticate"
      default_redirection_url: "${config.domain}"${config.enableRedis ? `
  redis:
    host: "redis"
    port: 6379` : ''}

regulation:
  max_retries: 5
  find_time: "2 minutes"
  ban_time: "10 minutes"

storage:
  encryption_key: '{{ env "AUTHELIA_STORAGE_ENCRYPTION_KEY" }}'

  postgres:
    address: '{{ env "AUTHELIA_STORAGE_POSTGRES_ADDRESS" }}'
    database: '{{ env "AUTHELIA_STORAGE_POSTGRES_DATABASE" }}'
    schema: '{{ env "AUTHELIA_STORAGE_POSTGRES_SCHEMA" }}'
    username: '{{ env "AUTHELIA_STORAGE_POSTGRES_USERNAME" }}'
    password: '{{ env "AUTHELIA_STORAGE_POSTGRES_PASSWORD" }}'
    timeout: "5 seconds"

notifier:
  # filesystem notifier can't send real emails — disable the startup connectivity check
  disable_startup_check: true

  filesystem:
    filename: "/config/notification.txt"
`;
}

function generateCaddyfile(config) {
  const { enableAuthelia } = config;
  return `import /etc/caddy/snippets/cors.conf

{$DOMAIN} {
  @supa_api path /rest/v1/* /auth/v1/* /realtime/v1/* /functions/v1/* /mcp /api/mcp
${enableAuthelia ? `
  @authelia path /authenticate /authenticate/*
  handle @authelia {
    reverse_proxy authelia:9091
  }
` : ''}
  handle @supa_api {
    reverse_proxy kong:8000
  }

  handle_path /storage/v1/* {
    import cors *
    reverse_proxy storage:5000 {
      header_up X-Forwarded-Prefix /{http.request.orig_uri.path.0}/{http.request.orig_uri.path.1}
    }
  }

  handle_path /goapi/* {
    reverse_proxy kong:8000
  }

  handle_path /admin/* {
${enableAuthelia ? `    forward_auth authelia:9091 {
      uri /api/authz/forward-auth
      copy_headers Remote-User Remote-Groups Remote-Name Remote-Email
    }` : `    basic_auth {
      {$PROXY_AUTH_USERNAME} {$PROXY_AUTH_PASSWORD}
    }`}
    reverse_proxy management:3001
  }

  handle {
${enableAuthelia ? `    forward_auth authelia:9091 {
      uri /api/authz/forward-auth
      copy_headers Remote-User Remote-Groups Remote-Name Remote-Email
    }` : `    basic_auth {
      {$PROXY_AUTH_USERNAME} {$PROXY_AUTH_PASSWORD}
    }`}
    reverse_proxy supabase-studio:3000
  }

  header -server
  header X-Content-Type-Options nosniff
  header X-Frame-Options SAMEORIGIN
  header Referrer-Policy strict-origin-when-cross-origin
  header Permissions-Policy "camera=(), microphone=(), geolocation=()"
}
`;
}

function generateCorsConf() {
  return `(cors) {
  @origin header Origin {args[0]}
  header @origin Access-Control-Allow-Origin "{args[0]}"
  header @origin Access-Control-Allow-Methods "GET, POST, PUT, PATCH, DELETE, OPTIONS"
  header @origin Access-Control-Allow-Headers "Authorization, Content-Type, Accept, apikey, x-client-info"
  header @origin Access-Control-Max-Age "3600"
}
`;
}

// ── Main cloud-init generator ───────────────────────────────────────────────

export async function generateCloudInit(config, secrets) {
  const {
    serverName, deployUser, domain, supabaseUser, supabasePassword,
    supabaseEmail, displayName, enableAuthelia, enableRedis,
    s3Bucket, s3Region, s3AccessKey, s3SecretKey,
    healthcheckUrl,
    smtpHost, smtpPort, smtpUser, smtpPass, smtpSenderName, smtpAdminEmail,
    siteUrl, additionalRedirectUrls,
  } = config;

  // Build tarball of static config files
  const tarFiles = [
    { name: 'volumes/api/kong.yml', content: getKongYml(secrets.anonKey, secrets.serviceRoleKey, 'supabase', 'not_being_used') },
    { name: 'volumes/db/realtime.sql', content: getRealtimeSql() },
    { name: 'volumes/db/roles.sql', content: getRolesSql() },
    { name: 'volumes/db/webhooks.sql', content: getWebhooksSql() },
    { name: 'volumes/db/_supabase.sql', content: getSupabaseSql() },
    { name: 'volumes/db/jwt.sql', content: getJwtSql() },
    { name: 'volumes/db/logs.sql', content: getLogsSql() },
    { name: 'volumes/db/pooler.sql', content: getPoolerSql() },
    { name: 'volumes/logs/vector.yml', content: getVectorYml() },
    { name: 'volumes/pooler/pooler.exs', content: getPoolerExs() },
    { name: 'volumes/functions/main/index.ts', content: getFunctionsMainIndex() },
    { name: 'volumes/functions/hello/index.ts', content: getFunctionsHelloIndex() },
  ];
  if (enableAuthelia) {
    tarFiles.push({ name: 'volumes/db/schema-authelia.sh', content: getSchemaAutheliaSh() });
  }

  const tarData = createTar(tarFiles);
  const payload = await gzipAndBase64(tarData);

  // Build dynamic configs
  const envFile = generateEnvFile(config, secrets);
  const composeFile = generateDockerCompose(config);
  const caddyfile = generateCaddyfile(config);
  const corsConf = generateCorsConf();

  // Authelia env vars to append to .env
  let autheliaEnvVars = '';
  if (enableAuthelia) {
    autheliaEnvVars = `
AUTHELIA_SESSION_SECRET=${secrets.autheliaSessionSecret}
AUTHELIA_STORAGE_ENCRYPTION_KEY=${secrets.autheliaStorageEncKey}
AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET=${secrets.autheliaJwtSecret}`;
  } else {
    autheliaEnvVars = `
PROXY_AUTH_USERNAME=${supabaseUser}`;
    // PROXY_AUTH_PASSWORD will be set after hashing
  }

  const script = `#!/bin/bash
set -euo pipefail
exec > /var/log/supabase-deploy.log 2>&1

# ── Status reporter: updates this server's labels via Hetzner API ──
HETZNER_TOKEN="${config.hetznerCloudToken}"
SERVER_ID=$(curl -s http://169.254.169.254/hetzner/v1/metadata/instance-id 2>/dev/null || echo "")
update_status() {
  if [ -n "$SERVER_ID" ] && [ -n "$HETZNER_TOKEN" ]; then
    curl -s -X PUT "https://api.hetzner.cloud/v1/servers/\${SERVER_ID}" \\
      -H "Authorization: Bearer \${HETZNER_TOKEN}" \\
      -H "Content-Type: application/json" \\
      -d "{\\"labels\\":{\\"deploy_phase\\":\\"\$1\\",\\"managed_by\\":\\"supabase-deploy\\"}}" >/dev/null 2>&1 || true
  fi
}

trap 'update_status "failed"' ERR

update_status "starting"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: SYSTEM HARDENING
# ═══════════════════════════════════════════════════════════════════════════════
update_status "hardening"
export DEBIAN_FRONTEND=noninteractive

# Wait for any running apt/dpkg processes to finish
for i in $(seq 1 60); do
  if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; then
    echo "Waiting for apt lock (attempt $i/60)..."
    sleep 5
  else
    break
  fi
done
if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
  echo "Force-killing blocking apt processes..."
  killall -9 apt-get dpkg unattended-upgrade 2>/dev/null || true
  sleep 3
  dpkg --configure -a
fi

apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \\
  curl wget jq openssl ufw fail2ban \\
  unattended-upgrades apt-listchanges \\
  net-tools htop sysstat apparmor apparmor-utils \\
  libpam-pwquality apt-transport-https ca-certificates gnupg lsb-release \\
  apache2-utils

update_status "packages_done"

# ── Create deploy user ──
DEPLOY_USER="${deployUser}"
if ! id "$DEPLOY_USER" &>/dev/null; then
  adduser --disabled-password --gecos "" "$DEPLOY_USER"
  usermod -aG sudo "$DEPLOY_USER"
fi
DEPLOY_HOME=$(eval echo "~$DEPLOY_USER")
mkdir -p "$DEPLOY_HOME/.ssh"
cp /root/.ssh/authorized_keys "$DEPLOY_HOME/.ssh/authorized_keys"
chmod 700 "$DEPLOY_HOME/.ssh"
chmod 600 "$DEPLOY_HOME/.ssh/authorized_keys"
chown -R "$DEPLOY_USER:$DEPLOY_USER" "$DEPLOY_HOME/.ssh"
echo "$DEPLOY_USER ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$DEPLOY_USER"
chmod 440 "/etc/sudoers.d/$DEPLOY_USER"
echo "umask 027" >> "$DEPLOY_HOME/.bashrc"

update_status "ssh_hardening"

# ── SSH Hardening (Phase 1: keep root accessible for debugging) ──
cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%s)"
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-hardening.conf <<SSHCONF
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 5
MaxSessions 5
LoginGraceTime 60
SSHCONF
if sshd -t; then
  systemctl restart ssh
else
  echo "WARNING: sshd config test failed, reverting..."
  cat > /etc/ssh/sshd_config.d/99-hardening.conf <<SSHCONF2
PasswordAuthentication no
UsePAM yes
SSHCONF2
  sshd -t && systemctl restart ssh
fi

update_status "kernel_hardening"

# ── Kernel hardening ──
cat > /etc/sysctl.d/99-hardening.conf <<'SYSCTL'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
SYSCTL

# ── Performance tuning ──
TOTAL_RAM_MB=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo || echo 4096)
TOTAL_RAM_MB=\${TOTAL_RAM_MB:-4096}
if [ "$TOTAL_RAM_MB" -ge 16384 ]; then FD=524288; SOMAX=4096; TCP_RMEM="4096 87380 16777216"; TCP_WMEM="4096 65536 16777216"; NETDEV_BUDGET=600
elif [ "$TOTAL_RAM_MB" -ge 8192 ]; then FD=262144; SOMAX=4096; TCP_RMEM="4096 87380 16777216"; TCP_WMEM="4096 65536 16777216"; NETDEV_BUDGET=600
elif [ "$TOTAL_RAM_MB" -ge 4096 ]; then FD=131072; SOMAX=2048; TCP_RMEM="4096 87380 6291456"; TCP_WMEM="4096 65536 6291456"; NETDEV_BUDGET=300
else FD=131072; SOMAX=2048; TCP_RMEM="4096 87380 6291456"; TCP_WMEM="4096 65536 6291456"; NETDEV_BUDGET=300; fi

cat > /etc/sysctl.d/99-performance.conf <<PERF
fs.file-max = $FD
fs.nr_open = $FD
net.core.somaxconn = $SOMAX
net.core.netdev_max_backlog = 5000
net.core.netdev_budget = $NETDEV_BUDGET
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_rmem = $TCP_RMEM
net.ipv4.tcp_wmem = $TCP_WMEM
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.ip_local_port_range = 1024 65535
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.vfs_cache_pressure = 50
vm.overcommit_memory = 0
PERF

sysctl --system >/dev/null 2>&1

cat > /etc/security/limits.d/99-supabase.conf <<LIM
* soft nofile $FD
* hard nofile $FD
root soft nofile $FD
root hard nofile $FD
LIM

# ── I/O scheduler: none for SSD/NVMe ──
for disk in /sys/block/sd* /sys/block/vd* /sys/block/nvme*; do
  [ -d "$disk" ] || continue
  rot=$(cat "$disk/queue/rotational" 2>/dev/null || echo 1)
  if [ "$rot" -eq 0 ] && [ -f "$disk/queue/scheduler" ]; then
    echo "none" > "$disk/queue/scheduler" 2>/dev/null || true
  fi
done

# ── Swap ──
update_status "swap"
if [ "$TOTAL_RAM_MB" -le 2048 ]; then SWAP=$((TOTAL_RAM_MB * 2))
elif [ "$TOTAL_RAM_MB" -le 8192 ]; then SWAP=$TOTAL_RAM_MB
elif [ "$TOTAL_RAM_MB" -le 65536 ]; then SWAP=$((TOTAL_RAM_MB / 2)); [ "$SWAP" -lt 4096 ] && SWAP=4096
else SWAP=4096; fi

dd if=/dev/zero of=/swapfile bs=1M count=$SWAP status=none
chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
echo "/swapfile none swap sw 0 0" >> /etc/fstab

# ── Firewall ──
update_status "firewall"
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw limit 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp
ufw --force enable

# ── Fail2ban ──
cat > /etc/fail2ban/jail.local <<F2B
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = systemd
banaction = ufw
[sshd]
enabled = true
port = 22
maxretry = 5
F2B
systemctl enable fail2ban && systemctl restart fail2ban

# ── Auto-updates ──
cat > /etc/apt/apt.conf.d/20auto-upgrades <<AU
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AU

cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'UNATTENDED'
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
UNATTENDED
systemctl enable unattended-upgrades

# ── Shared memory hardening ──
if ! grep -q "tmpfs.*/run/shm" /etc/fstab; then
  echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
fi

# ── Docker ──
update_status "docker"
for attempt in 1 2 3; do
  if curl -fsSL --connect-timeout 15 --max-time 120 https://get.docker.com | sh; then
    break
  fi
  echo "Docker install attempt $attempt failed, retrying in 5s..."
  sleep 5
done

mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<DOCKER
{
  "log-driver":"json-file",
  "log-opts":{"max-size":"10m","max-file":"3"},
  "storage-driver":"overlay2",
  "live-restore":true,
  "userland-proxy":false,
  "no-new-privileges":true,
  "default-ulimits":{"nofile":{"Name":"nofile","Hard":$FD,"Soft":$FD}}
}
DOCKER
systemctl restart docker
usermod -aG docker "$DEPLOY_USER"

update_status "hardening_done"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: SUPABASE DEPLOYMENT (no git, no yq, no sed — all inlined)
# ═══════════════════════════════════════════════════════════════════════════════
update_status "supabase"

mkdir -p /root/supabase/docker/volumes/{api,db/init,logs,pooler,functions/main,functions/hello,caddy/snippets,storage,snippets,redis}
${enableAuthelia ? 'mkdir -p /root/supabase/docker/volumes/authelia' : ''}
cd /root/supabase/docker

# ── Extract static config files from embedded tarball ──
base64 -d <<'PAYLOAD_EOF' | gzip -d | tar x -C /root/supabase/docker
${payload}
PAYLOAD_EOF
${enableAuthelia ? `
chmod +x volumes/db/schema-authelia.sh` : ''}

update_status "supabase_env"

# ── Hash password with bcrypt ──
HASHED_PW=$(htpasswd -bnBC 12 "" '${supabasePassword.replace(/'/g, "'\\''")}' | cut -d: -f2)

# ── Write .env (secrets already interpolated from JS) ──
cat > .env <<'ENV_EOF'
${envFile}${autheliaEnvVars}
ENV_EOF
${!enableAuthelia ? `echo "PROXY_AUTH_PASSWORD='\${HASHED_PW}'" >> .env` : ''}
chmod 644 .env

# ── Write docker-compose.yml ──
cat > docker-compose.yml <<'COMPOSE_EOF'
${composeFile}
COMPOSE_EOF

update_status "supabase_caddy"

${enableAuthelia ? `# ── Write Authelia configuration ──
cat > volumes/authelia/configuration.yml <<'AUTHELIA_EOF'
${generateAutheliaConfig(config)}
AUTHELIA_EOF

# ── Write Authelia users database (needs $HASHED_PW expansion) ──
cat > volumes/authelia/users_database.yml <<USERS_EOF
users:
  ${supabaseUser}:
    displayname: "${displayName}"
    password: "$HASHED_PW"
    email: "${supabaseEmail}"
    groups:
      - "admins"
      - "dev"
    disabled: false
USERS_EOF
chmod 600 volumes/authelia/users_database.yml
` : ''}

update_status "supabase_caddyfile"

# ── Write Caddyfile ──
mkdir -p volumes/caddy/snippets
cat > volumes/caddy/Caddyfile <<'CADDY_EOF'
${caddyfile}
CADDY_EOF

cat > volumes/caddy/snippets/cors.conf <<'CORS_EOF'
${corsConf}
CORS_EOF

# ── Pull and start ──
update_status "pulling"
for attempt in 1 2 3; do
  if docker compose pull 2>&1; then
    break
  fi
  echo "docker compose pull attempt $attempt failed, retrying in 15s..."
  sleep 15
done

update_status "starting_containers"
docker compose up -d

# Wait for containers to stabilize
sleep 10

# Verify key containers are running
for svc in supabase-db supabase-kong caddy-container; do
  if ! docker ps --format '{{.Names}}' | grep -q "^$svc\$"; then
    echo "WARNING: $svc is not running!"
    docker logs "$svc" 2>&1 | tail -20 || true
  fi
done
${enableAuthelia ? `
# ── Register pre-generated TOTP secret via Authelia CLI ──────────────────────
# IMPORTANT: Authelia encrypts TOTP secrets with AUTHELIA_STORAGE_ENCRYPTION_KEY
# before storing them. A raw psql INSERT bypasses this and produces an
# unreadable row. The CLI handles encryption automatically.
echo "Registering TOTP secret via Authelia CLI..."
for i in $(seq 1 24); do
  if docker exec authelia authelia storage user list >/dev/null 2>&1; then
    echo "Authelia storage is ready."
    break
  fi
  echo "  attempt $i/24 — waiting 5s..."
  sleep 5
done

docker exec authelia authelia storage user totp generate "${supabaseUser}" \
  --secret "${secrets.totpSecret}" \
  --issuer "${host}" \
  --algorithm SHA1 \
  --digits 6 \
  --period 30 \
  && echo "TOTP registered successfully." \
  || echo "WARNING: Could not pre-register TOTP. Run manually: docker exec authelia authelia storage user totp generate ${supabaseUser} --secret ${secrets.totpSecret}"
` : ''}
update_status "supabase_done"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: S3 BACKUP SETUP
# ═══════════════════════════════════════════════════════════════════════════════
set +e
update_status "s3_backup"

S3_REPO="s3:s3.${s3Region}.amazonaws.com/${s3Bucket}/${serverName}"

update_status "backup_init"
apt-get install -y -qq restic

# Write the backup script
# Write backup script (base64-encoded to avoid heredoc escaping issues)
echo 'IyEvYmluL2Jhc2gKIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwojIHN1cGFiYXNlLWJhY2t1cC5zaCAgdjIg4oCUIG11bHRpLXNlcnZlciBlZGl0aW9uCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiMgQ29tcHJlaGVuc2l2ZSwgZW5jcnlwdGVkLCBkZWR1cGxpY2F0ZWQgYmFja3VwIGZvciBzZWxmLWhvc3RlZCBTdXBhYmFzZS4KIyBEZXNpZ25lZCBmb3IgbXVsdGlwbGUgU3VwYWJhc2UgaW5zdGFuY2VzIGJhY2tpbmcgdXAgdG8gT05FIEhldHpuZXIKIyBTdG9yYWdlIEJveCAob3IgUzMtY29tcGF0aWJsZSB0YXJnZXQpLgojCiMgQmFja3MgdXA6CiMgICAxLiBQb3N0Z3JlcyBkYXRhYmFzZSAocGdfZHVtcGFsbCDigJQgZnVsbCBjb25zaXN0ZW50IHNuYXBzaG90KQojICAgMi4gU3RvcmFnZSBvYmplY3RzICAgKE1pbklPIC8gbG9jYWwgdm9sdW1lIOKAlCBkZWR1cGxpY2F0ZWQgYnkgcmVzdGljKQojICAgMy4gQ29uZmlnIGZpbGVzICAgICAgKC5lbnYsIGNvbXBvc2UsIGNhZGR5L25naW54LCBhdXRoZWxpYSkKIwojIE11bHRpLXNlcnZlciBsYXlvdXQgb24gU3RvcmFnZSBCb3g6CiMgICAvYmFja3Vwcy8KIyAgICAg4pSc4pSA4pSAIHN1cGFiYXNlLXByb2QvICAgICAgICDihpAgU0VSVkVSX05BTUU9c3VwYWJhc2UtcHJvZAojICAgICDilIIgICDilJTilIDilIAgcmVzdGljLXJlcG8KIyAgICAg4pSc4pSA4pSAIHN1cGFiYXNlLXN0YWdpbmcvICAgICDihpAgU0VSVkVSX05BTUU9c3VwYWJhc2Utc3RhZ2luZwojICAgICDilIIgICDilJTilIDilIAgcmVzdGljLXJlcG8KIyAgICAg4pSU4pSA4pSAIHN1cGFiYXNlLWNsaWVudC14LyAgICDihpAgU0VSVkVSX05BTUU9c3VwYWJhc2UtY2xpZW50LXgKIyAgICAgICAgIOKUlOKUgOKUgCByZXN0aWMtcmVwbwojCiMgRWFjaCBzZXJ2ZXIgaGFzIGl0cyBvd24gcmVzdGljIHJlcG8gKyBlbmNyeXB0aW9uIGtleS4KIyBPbmUgY29tcHJvbWlzZWQgc2VydmVyIGNhbm5vdCByZWFkIGFub3RoZXIncyBiYWNrdXBzLgojCiMgU2V0dXAgKHBlciBzZXJ2ZXIpOgojICAgMS4gSW5zdGFsbCByZXN0aWM6ICAgICAgICAgIHN1ZG8gYXB0IGluc3RhbGwgcmVzdGljCiMgICAyLiBDb3B5IGNvbmZpZzogICAgICAgICAgICAgY3AgYmFja3VwLmVudi5leGFtcGxlIGJhY2t1cC5lbnYKIyAgIDMuIEVkaXQgY29uZmlnOiAgICAgICAgICAgICBuYW5vIGJhY2t1cC5lbnYgIChzZXQgU0VSVkVSX05BTUUgKyBjcmVkcykKIyAgIDQuIEluaXQgcmVwbzogICAgICAgICAgICAgICAuL3N1cGFiYXNlLWJhY2t1cC5zaCAtLWluaXQKIyAgIDUuIFRlc3Q6ICAgICAgICAgICAgICAgICAgICAuL3N1cGFiYXNlLWJhY2t1cC5zaCAtLW5vdwojICAgNi4gSW5zdGFsbCBjcm9uOiAgICAgICAgICAgIHN1ZG8gLi9zdXBhYmFzZS1iYWNrdXAuc2ggLS1pbnN0YWxsLWNyb24KIwojIENvbW1hbmRzOgojICAgLS1pbml0ICAgICAgICAgICAgICBJbml0aWFsaXplIHJlc3RpYyByZXBvc2l0b3J5IGZvciB0aGlzIHNlcnZlcgojICAgLS1ub3cgICAgICAgICAgICAgICBSdW4gYmFja3VwIGltbWVkaWF0ZWx5CiMgICAtLWxpc3QgICAgICAgICAgICAgIExpc3Qgc25hcHNob3RzIGZvciB0aGlzIHNlcnZlcgojICAgLS1zdGF0cyAgICAgICAgICAgICBTaG93IHJlcG9zaXRvcnkgc2l6ZSBhbmQgc25hcHNob3QgY291bnQKIyAgIC0tdmVyaWZ5ICAgICAgICAgICAgVmVyaWZ5IHJlcG9zaXRvcnkgaW50ZWdyaXR5ICgxMCUgc2FtcGxlKQojICAgLS1yZXN0b3JlIFNOQVAgICAgICBSZXN0b3JlIGEgc25hcHNob3QgaW50ZXJhY3RpdmVseQojICAgLS1yZXN0b3JlLWRiIFNOQVAgICBSZXN0b3JlIG9ubHkgdGhlIGRhdGFiYXNlIGZyb20gYSBzbmFwc2hvdAojICAgLS1pbnN0YWxsLWNyb24gICAgICBJbnN0YWxsIGRhaWx5IDNhbSBjcm9uICsgbG9nIHJvdGF0aW9uCiMgICAtLXVuaW5zdGFsbC1jcm9uICAgIFJlbW92ZSB0aGUgY3JvbiBqb2IKIyAgIC0tdGVzdC1ub3RpZnkgICAgICAgVGVzdCB0aGUgaGVhbHRoLWNoZWNrIG5vdGlmaWNhdGlvbgojIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjCgpzZXQgLWV1byBwaXBlZmFpbAoKU0NSSVBUX0RJUj0iJChjZCAiJChkaXJuYW1lICIke0JBU0hfU09VUkNFWzBdfSIpIiAmJiBwd2QpIgpCQUNLVVBfQ09ORj0iJHtTQ1JJUFRfRElSfS9iYWNrdXAuZW52IgpTVEFUVVNfRklMRT0iJHtTQ1JJUFRfRElSfS9iYWNrdXAtc3RhdHVzLmpzb24iCgojIOKUgOKUgCBDb2xvcnMg4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSACk5PX0NPTE9SPScnIFJFRD0nJyBDWUFOPScnIEdSRUVOPScnIFlFTExPVz0nJwppZiBbIC10IDEgXTsgdGhlbgogICAgbmM9JCh0cHV0IGNvbG9ycyAyPi9kZXYvbnVsbCB8fCBlY2hvIDApCiAgICBpZiBbICIkbmMiIC1nZSA4IF07IHRoZW4KICAgICAgICBOT19DT0xPUj0nXDAzM1swbSc7IFJFRD0nXDAzM1swOzMxbSc7IENZQU49J1wwMzNbMDszNm0nCiAgICAgICAgR1JFRU49J1wwMzNbMDszMm0nOyBZRUxMT1c9J1wwMzNbMDszM20nCiAgICBmaQpmaQoKdHMoKSB7IGRhdGUgJyslWS0lbS0lZCAlSDolTTolUyc7IH0KaW5mbygpICB7IGVjaG8gLWUgIiR7Q1lBTn1bSU5GT10ke05PX0NPTE9SfSAgJCh0cykgICQqIjsgfQpvaygpICAgIHsgZWNobyAtZSAiJHtHUkVFTn1bIE9LIF0ke05PX0NPTE9SfSAgJCh0cykgICQqIjsgfQp3YXJuKCkgIHsgZWNobyAtZSAiJHtZRUxMT1d9W1dBUk5dJHtOT19DT0xPUn0gICQodHMpICAkKiI7IH0KZmFpbCgpICB7IGVjaG8gLWUgIiR7UkVEfVtGQUlMXSR7Tk9fQ09MT1J9ICAkKHRzKSAgJCoiOyBleGl0IDE7IH0KCiMg4pSA4pSAIExvYWQgY29uZmlnIOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgAppZiBbICEgLWYgIiRCQUNLVVBfQ09ORiIgXTsgdGhlbgogICAgZmFpbCAiQ29uZmlnIG5vdCBmb3VuZDogJEJBQ0tVUF9DT05GXG4gIFJ1bjogY3AgYmFja3VwLmVudi5leGFtcGxlIGJhY2t1cC5lbnYgJiYgbmFubyBiYWNrdXAuZW52IgpmaQoKIyBzaGVsbGNoZWNrIGRpc2FibGU9U0MxMDkwCnNvdXJjZSAiJEJBQ0tVUF9DT05GIgoKIyDilIDilIAgVmFsaWRhdGUgcmVxdWlyZWQgdmFycyDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIAKOiAiJHtTRVJWRVJfTkFNRTo/U2V0IFNFUlZFUl9OQU1FIGluIGJhY2t1cC5lbnYgKGUuZy4gc3VwYWJhc2UtcHJvZCl9Igo6ICIke0JBQ0tVUF9CQUNLRU5EOj9TZXQgQkFDS1VQX0JBQ0tFTkQgaW4gYmFja3VwLmVudiAoaGV0em5lciBvciBzMyl9Igo6ICIke1JFU1RJQ19QQVNTV09SRDo/U2V0IFJFU1RJQ19QQVNTV09SRCBpbiBiYWNrdXAuZW52fSIKOiAiJHtTVVBBQkFTRV9ET0NLRVJfRElSOj9TZXQgU1VQQUJBU0VfRE9DS0VSX0RJUiBpbiBiYWNrdXAuZW52fSIKCiMgRGVmYXVsdHMKOiAiJHtQT1NUR1JFU19DT05UQUlORVI6PXN1cGFiYXNlLWRifSIKOiAiJHtQT1NUR1JFU19VU0VSOj1wb3N0Z3Jlc30iCjogIiR7UkVURU5USU9OX0RBSUxZOj03fSIKOiAiJHtSRVRFTlRJT05fV0VFS0xZOj00fSIKOiAiJHtSRVRFTlRJT05fTU9OVEhMWTo9Nn0iCjogIiR7SEVBTFRIQ0hFQ0tfVVJMOj19Igo6ICIke0hFQUxUSENIRUNLX01FVEhPRDo9c2ltcGxlfSIKCiMgVmFsaWRhdGUgU0VSVkVSX05BTUUgKGFscGhhbnVtZXJpYywgaHlwaGVucywgdW5kZXJzY29yZXMgb25seSkKaWYgW1sgISAiJFNFUlZFUl9OQU1FIiA9fiBeW2EtekEtWjAtOV8tXSskIF1dOyB0aGVuCiAgICBmYWlsICJTRVJWRVJfTkFNRSBtdXN0IGJlIGFscGhhbnVtZXJpYyB3aXRoIGh5cGhlbnMvdW5kZXJzY29yZXMgb25seS4gR290OiAkU0VSVkVSX05BTUUiCmZpCgojIOKUgOKUgCBCdWlsZCByZXN0aWMgcmVwbyBVUkwg4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSACmV4cG9ydCBSRVNUSUNfUEFTU1dPUkQKCmNhc2UgIiRCQUNLVVBfQkFDS0VORCIgaW4KICAgIGhldHpuZXIpCiAgICAgICAgOiAiJHtIRVRaTkVSX1NUT1JBR0VCT1hfVVNFUjo/U2V0IEhFVFpORVJfU1RPUkFHRUJPWF9VU0VSfSIKICAgICAgICA6ICIke0hFVFpORVJfU1RPUkFHRUJPWF9IT1NUOj9TZXQgSEVUWk5FUl9TVE9SQUdFQk9YX0hPU1R9IgogICAgICAgIDogIiR7SEVUWk5FUl9TVE9SQUdFQk9YX0JBU0U6PS9iYWNrdXBzfSIKICAgICAgICBleHBvcnQgUkVTVElDX1JFUE9TSVRPUlk9InNmdHA6JHtIRVRaTkVSX1NUT1JBR0VCT1hfVVNFUn1AJHtIRVRaTkVSX1NUT1JBR0VCT1hfSE9TVH06JHtIRVRaTkVSX1NUT1JBR0VCT1hfQkFTRX0vJHtTRVJWRVJfTkFNRX0iCiAgICAgICAgOzsKICAgIHMzKQogICAgICAgIDogIiR7QVdTX0FDQ0VTU19LRVlfSUQ6P1NldCBBV1NfQUNDRVNTX0tFWV9JRH0iCiAgICAgICAgOiAiJHtBV1NfU0VDUkVUX0FDQ0VTU19LRVk6P1NldCBBV1NfU0VDUkVUX0FDQ0VTU19LRVl9IgogICAgICAgIDogIiR7UzNfQlVDS0VUOj9TZXQgUzNfQlVDS0VUfSIKICAgICAgICA6ICIke1MzX0VORFBPSU5UOj19IgogICAgICAgIGV4cG9ydCBBV1NfQUNDRVNTX0tFWV9JRCBBV1NfU0VDUkVUX0FDQ0VTU19LRVkKICAgICAgICBpZiBbIC1uICIkUzNfRU5EUE9JTlQiIF07IHRoZW4KICAgICAgICAgICAgZXhwb3J0IFJFU1RJQ19SRVBPU0lUT1JZPSJzMzoke1MzX0VORFBPSU5UfS8ke1MzX0JVQ0tFVH0vJHtTRVJWRVJfTkFNRX0iCiAgICAgICAgZWxzZQogICAgICAgICAgICBleHBvcnQgUkVTVElDX1JFUE9TSVRPUlk9InMzOnMzLmFtYXpvbmF3cy5jb20vJHtTM19CVUNLRVR9LyR7U0VSVkVSX05BTUV9IgogICAgICAgIGZpCiAgICAgICAgOzsKICAgICopCiAgICAgICAgZmFpbCAiQkFDS1VQX0JBQ0tFTkQgbXVzdCBiZSAnaGV0em5lcicgb3IgJ3MzJyIKICAgICAgICA7Owplc2FjCgojIOKUgOKUgCBWZXJpZnkgZGVwZW5kZW5jaWVzIOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgApjb21tYW5kIC12IHJlc3RpYyAmPi9kZXYvbnVsbCB8fCBmYWlsICJyZXN0aWMgbm90IGluc3RhbGxlZC4gUnVuOiBzdWRvIGFwdCBpbnN0YWxsIHJlc3RpYyIKY29tbWFuZCAtdiBkb2NrZXIgJj4vZGV2L251bGwgfHwgZmFpbCAiZG9ja2VyIG5vdCBpbnN0YWxsZWQiCgojIFN0YWdpbmcgYXJlYSDigJQgY2xlYW5lZCB1cCBvbiBleGl0ClNUQUdJTkdfRElSPSIiCmNsZWFudXAoKSB7CiAgICBbIC1uICIkU1RBR0lOR19ESVIiIF0gJiYgcm0gLXJmICIkU1RBR0lOR19ESVIiCn0KdHJhcCBjbGVhbnVwIEVYSVQKCiMg4pSA4pSAIEhlYWx0aC1jaGVjayBub3RpZmljYXRpb24g4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSACiMgU3VwcG9ydHM6CiMgICAtIHNpbXBsZTogICAgR0VUIHJlcXVlc3Qgb24gc3VjY2VzcywgL2ZhaWwgb24gZmFpbHVyZSAoaGVhbHRoY2hlY2tzLmlvLCB1cHRpbWUga3VtYSBwdXNoKQojICAgLSBudGZ5OiAgICAgIFBPU1QgdG8gbnRmeS5zaCB0b3BpYwojICAgLSBzbGFjazogICAgIFBPU1QgdG8gU2xhY2sgd2ViaG9vawojICAgLSBkaXNjb3JkOiAgIFBPU1QgdG8gRGlzY29yZCB3ZWJob29rCiMgICAtIG5vbmU6ICAgICAgZGlzYWJsZWQKbm90aWZ5KCkgewogICAgbG9jYWwgc3RhdHVzPSIkMSIgICMgIm9rIiBvciAiZmFpbCIKICAgIGxvY2FsIG1lc3NhZ2U9IiQyIgoKICAgIFsgLXogIiRIRUFMVEhDSEVDS19VUkwiIF0gJiYgcmV0dXJuIDAKCiAgICBjYXNlICIkSEVBTFRIQ0hFQ0tfTUVUSE9EIiBpbgogICAgICAgIHNpbXBsZSkKICAgICAgICAgICAgaWYgWyAiJHN0YXR1cyIgPSAib2siIF07IHRoZW4KICAgICAgICAgICAgICAgIGN1cmwgLWZzUyAtbSAxMCAtLXJldHJ5IDMgIiRIRUFMVEhDSEVDS19VUkwiID4vZGV2L251bGwgMj4mMSB8fCB0cnVlCiAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgIGN1cmwgLWZzUyAtbSAxMCAtLXJldHJ5IDMgIiRIRUFMVEhDSEVDS19VUkwvZmFpbCIgPi9kZXYvbnVsbCAyPiYxIHx8IHRydWUKICAgICAgICAgICAgZmkKICAgICAgICAgICAgOzsKICAgICAgICBudGZ5KQogICAgICAgICAgICBsb2NhbCBwcmlvcml0eT0iMyIKICAgICAgICAgICAgbG9jYWwgdGFncz0id2hpdGVfY2hlY2tfbWFyayIKICAgICAgICAgICAgaWYgWyAiJHN0YXR1cyIgPSAiZmFpbCIgXTsgdGhlbiBwcmlvcml0eT0iNSI7IHRhZ3M9IngiOyBmaQogICAgICAgICAgICBjdXJsIC1mc1MgLW0gMTAgXAogICAgICAgICAgICAgICAgLUggIlRpdGxlOiBCYWNrdXAgJHtzdGF0dXN9OiAke1NFUlZFUl9OQU1FfSIgXAogICAgICAgICAgICAgICAgLUggIlByaW9yaXR5OiAkcHJpb3JpdHkiIFwKICAgICAgICAgICAgICAgIC1IICJUYWdzOiAkdGFncyIgXAogICAgICAgICAgICAgICAgLWQgIiRtZXNzYWdlIiBcCiAgICAgICAgICAgICAgICAiJEhFQUxUSENIRUNLX1VSTCIgPi9kZXYvbnVsbCAyPiYxIHx8IHRydWUKICAgICAgICAgICAgOzsKICAgICAgICBzbGFja3xkaXNjb3JkKQogICAgICAgICAgICBsb2NhbCBjb2xvcj0iIzM2YTY0ZiIKICAgICAgICAgICAgWyAiJHN0YXR1cyIgPSAiZmFpbCIgXSAmJiBjb2xvcj0iI2ZmMDAwMCIKICAgICAgICAgICAgbG9jYWwgcGF5bG9hZAogICAgICAgICAgICBpZiBbICIkSEVBTFRIQ0hFQ0tfTUVUSE9EIiA9ICJzbGFjayIgXTsgdGhlbgogICAgICAgICAgICAgICAgcGF5bG9hZD0kKGNhdCA8PEVPSlNPTgp7ImF0dGFjaG1lbnRzIjpbeyJjb2xvciI6IiRjb2xvciIsInRpdGxlIjoiQmFja3VwICR7c3RhdHVzfTogJHtTRVJWRVJfTkFNRX0iLCJ0ZXh0IjoiJG1lc3NhZ2UiLCJ0cyI6JChkYXRlICslcyl9XX0KRU9KU09OCikKICAgICAgICAgICAgZWxzZQogICAgICAgICAgICAgICAgcGF5bG9hZD0ie1wiY29udGVudFwiOlwiKipCYWNrdXAgJHtzdGF0dXN9OiAke1NFUlZFUl9OQU1FfSoqXG4ke21lc3NhZ2V9XCJ9IgogICAgICAgICAgICBmaQogICAgICAgICAgICBjdXJsIC1mc1MgLW0gMTAgLUggIkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvbiIgXAogICAgICAgICAgICAgICAgLWQgIiRwYXlsb2FkIiAiJEhFQUxUSENIRUNLX1VSTCIgPi9kZXYvbnVsbCAyPiYxIHx8IHRydWUKICAgICAgICAgICAgOzsKICAgICAgICAqKQogICAgICAgICAgICAjIFNpbGVudGx5IHNraXAgdW5rbm93biBtZXRob2RzCiAgICAgICAgICAgIDs7CiAgICBlc2FjCn0KCiMg4pSA4pSAIFN0YXR1cyBmaWxlIOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgApfYmFja3VwX3N0YXJ0X3RpbWU9MApfYmFja3VwX3N0YXJ0X2lzbz0iIgpfZHVtcF9zaXplX2J5dGVzPTAKX3NuYXBzaG90X2lkPSIiCgp3cml0ZV9zdGF0dXMoKSB7CiAgICBsb2NhbCBzdWNjZXNzPSIkMSIKICAgIGxvY2FsIGVycm9yPSIkezI6LX0iCiAgICBsb2NhbCBlbGFwc2VkPSQoKCAkKGRhdGUgKyVzKSAtIF9iYWNrdXBfc3RhcnRfdGltZSApKQogICAgcHJpbnRmICd7InN1Y2Nlc3MiOiVzLCJ0aW1lc3RhbXAiOiIlcyIsInN0YXJ0ZWQiOiIlcyIsImR1cmF0aW9uX3NlY29uZHMiOiVzLCJkdW1wX3NpemVfYnl0ZXMiOiVzLCJzbmFwc2hvdF9pZCI6IiVzIiwiZXJyb3IiOiIlcyIsInNlcnZlcl9uYW1lIjoiJXMifVxuJyBcCiAgICAgICAgIiRzdWNjZXNzIiAiJChkYXRlIC1Jc2Vjb25kcykiICIkX2JhY2t1cF9zdGFydF9pc28iICIkZWxhcHNlZCIgIiRfZHVtcF9zaXplX2J5dGVzIiAiJF9zbmFwc2hvdF9pZCIgIiRlcnJvciIgIiRTRVJWRVJfTkFNRSIgPiAiJFNUQVRVU19GSUxFIgp9CgojIOKUgOKUgCBGdW5jdGlvbnMg4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSACgpkb19pbml0KCkgewogICAgaW5mbyAiSW5pdGlhbGl6aW5nIHJlc3RpYyByZXBvc2l0b3J5IGZvciAnJFNFUlZFUl9OQU1FJyIKICAgIGluZm8gIlJlcG9zaXRvcnk6ICRSRVNUSUNfUkVQT1NJVE9SWSIKICAgIHJlc3RpYyBpbml0CiAgICBvayAiUmVwb3NpdG9yeSBpbml0aWFsaXplZCBmb3IgJyRTRVJWRVJfTkFNRSciCiAgICBlY2hvICIiCiAgICBlY2hvICIgIFNBVkUgWU9VUiBSRVNUSUNfUEFTU1dPUkQgU09NRVdIRVJFIFNBRkUhIgogICAgZWNobyAiICBXaXRob3V0IGl0LCB5b3VyIGJhY2t1cHMgYXJlIFVOUkVDT1ZFUkFCTEUuIgogICAgZWNobyAiIgogICAgZWNobyAiICBSZXBvc2l0b3J5OiAkUkVTVElDX1JFUE9TSVRPUlkiCiAgICBlY2hvICIgIFNlcnZlcjogICAgICRTRVJWRVJfTkFNRSIKfQoKZG9fYmFja3VwKCkgewogICAgX2JhY2t1cF9zdGFydF90aW1lPSQoZGF0ZSArJXMpCiAgICBfYmFja3VwX3N0YXJ0X2lzbz0kKGRhdGUgLUlzZWNvbmRzKQogICAgX2R1bXBfc2l6ZV9ieXRlcz0wCiAgICBfc25hcHNob3RfaWQ9IiIKCiAgICBTVEFHSU5HX0RJUj0kKG1rdGVtcCAtZCAvdG1wL3N1cGFiYXNlLWJhY2t1cC0ke1NFUlZFUl9OQU1FfS5YWFhYWFgpCgogICAgaW5mbyAiWyRTRVJWRVJfTkFNRV0gU3RhcnRpbmcgYmFja3VwLi4uIgoKICAgICMg4pSA4pSAIDEuIFBvc3RncmVzIGR1bXAg4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSACiAgICBpbmZvICJbJFNFUlZFUl9OQU1FXSBEdW1waW5nIFBvc3RncmVzIGZyb20gY29udGFpbmVyICckUE9TVEdSRVNfQ09OVEFJTkVSJy4uLiIKICAgIGxvY2FsIGR1bXBfZmlsZT0iJFNUQUdJTkdfRElSL3Bvc3RncmVzX2R1bXAuc3FsLmd6IgoKICAgICMgV3JpdGUgc2VydmVyIG1ldGFkYXRhIGFsb25nc2lkZSB0aGUgZHVtcCBmb3IgZWFzaWVyIHJlc3RvcmUgaWRlbnRpZmljYXRpb24KICAgIGNhdCA+ICIkU1RBR0lOR19ESVIvYmFja3VwX21ldGFkYXRhLmpzb24iIDw8RU9KU09OCnsKICAgICJzZXJ2ZXJfbmFtZSI6ICIkU0VSVkVSX05BTUUiLAogICAgInRpbWVzdGFtcCI6ICIkKGRhdGUgLUlzZWNvbmRzKSIsCiAgICAicG9zdGdyZXNfY29udGFpbmVyIjogIiRQT1NUR1JFU19DT05UQUlORVIiLAogICAgInN1cGFiYXNlX2RpciI6ICIkU1VQQUJBU0VfRE9DS0VSX0RJUiIsCiAgICAiaG9zdG5hbWUiOiAiJChob3N0bmFtZSkiLAogICAgImlwIjogIiQoaG9zdG5hbWUgLUkgfCBhd2sgJ3twcmludCAkMX0nKSIKfQpFT0pTT04KCiAgICBpZiAhIGRvY2tlciBleGVjICIkUE9TVEdSRVNfQ09OVEFJTkVSIiBwZ19kdW1wYWxsIC1VICIkUE9TVEdSRVNfVVNFUiIgLS1jbGVhbiAyPi9kZXYvbnVsbCB8IGd6aXAgPiAiJGR1bXBfZmlsZSI7IHRoZW4KICAgICAgICBsb2NhbCBlcnJtc2c9InBnX2R1bXBhbGwgZmFpbGVkIgogICAgICAgIHdyaXRlX3N0YXR1cyBmYWxzZSAiJGVycm1zZyIKICAgICAgICBub3RpZnkgImZhaWwiICJbJFNFUlZFUl9OQU1FXSAkZXJybXNnIgogICAgICAgIGZhaWwgIlskU0VSVkVSX05BTUVdIFBvc3RncmVzIGR1bXAgRkFJTEVEIgogICAgZmkKCiAgICBfZHVtcF9zaXplX2J5dGVzPSQoc3RhdCAtYyVzICIkZHVtcF9maWxlIiAyPi9kZXYvbnVsbCB8fCBzdGF0IC1mJXogIiRkdW1wX2ZpbGUiIDI+L2Rldi9udWxsIHx8IGVjaG8gMCkKICAgIGxvY2FsIGR1bXBfc2l6ZQogICAgZHVtcF9zaXplPSQoZHUgLXNoICIkZHVtcF9maWxlIiB8IGN1dCAtZjEpCiAgICBvayAiWyRTRVJWRVJfTkFNRV0gUG9zdGdyZXMgZHVtcDogJGR1bXBfc2l6ZSIKCiAgICAjIOKUgOKUgCAyLiBTdGFnZSBjb25maWcgZmlsZXMg4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSACiAgICBsb2NhbCBjb25maWdfc3RhZ2luZz0iJFNUQUdJTkdfRElSL2NvbmZpZyIKICAgIG1rZGlyIC1wICIkY29uZmlnX3N0YWdpbmciCiAgICBsb2NhbCBjb25maWdfY291bnQ9MAoKICAgIGZvciBmIGluIFwKICAgICAgICAiJFNVUEFCQVNFX0RPQ0tFUl9ESVIvLmVudiIgXAogICAgICAgICIkU1VQQUJBU0VfRE9DS0VSX0RJUi9kb2NrZXItY29tcG9zZS55bWwiIFwKICAgICAgICAiJFNVUEFCQVNFX0RPQ0tFUl9ESVIvZG9ja2VyLWNvbXBvc2Uub3ZlcnJpZGUueW1sIiBcCiAgICAgICAgIiRTVVBBQkFTRV9ET0NLRVJfRElSL3ZvbHVtZXMvY2FkZHkvQ2FkZHlmaWxlIiBcCiAgICAgICAgIiRTVVBBQkFTRV9ET0NLRVJfRElSL3ZvbHVtZXMvbmdpbngvbmdpbngudGVtcGxhdGUiIFwKICAgICAgICAiJFNVUEFCQVNFX0RPQ0tFUl9ESVIvdm9sdW1lcy9hdXRoZWxpYS9jb25maWd1cmF0aW9uLnltbCIgXAogICAgICAgICIkU1VQQUJBU0VfRE9DS0VSX0RJUi92b2x1bWVzL2F1dGhlbGlhL3VzZXJzX2RhdGFiYXNlLnltbCI7IGRvCiAgICAgICAgaWYgWyAtZiAiJGYiIF07IHRoZW4KICAgICAgICAgICAgbG9jYWwgcmVsPSIke2YjIiRTVVBBQkFTRV9ET0NLRVJfRElSIi99IgogICAgICAgICAgICBta2RpciAtcCAiJGNvbmZpZ19zdGFnaW5nLyQoZGlybmFtZSAiJHJlbCIpIgogICAgICAgICAgICBjcCAiJGYiICIkY29uZmlnX3N0YWdpbmcvJHJlbCIKICAgICAgICAgICAgY29uZmlnX2NvdW50PSQoKGNvbmZpZ19jb3VudCArIDEpKQogICAgICAgIGZpCiAgICBkb25lCgogICAgIyBBbHNvIGdyYWIgc25pcHBldCBkaXJlY3RvcmllcyBpZiB0aGV5IGV4aXN0CiAgICBmb3IgZGlyIGluIFwKICAgICAgICAiJFNVUEFCQVNFX0RPQ0tFUl9ESVIvdm9sdW1lcy9jYWRkeS9zbmlwcGV0cyIgXAogICAgICAgICIkU1VQQUJBU0VfRE9DS0VSX0RJUi92b2x1bWVzL25naW54L3NuaXBwZXRzIjsgZG8KICAgICAgICBpZiBbIC1kICIkZGlyIiBdOyB0aGVuCiAgICAgICAgICAgIGxvY2FsIHJlbD0iJHtkaXIjIiRTVVBBQkFTRV9ET0NLRVJfRElSIi99IgogICAgICAgICAgICBta2RpciAtcCAiJGNvbmZpZ19zdGFnaW5nLyRyZWwiCiAgICAgICAgICAgIGNwIC1yICIkZGlyLyIqICIkY29uZmlnX3N0YWdpbmcvJHJlbC8iIDI+L2Rldi9udWxsIHx8IHRydWUKICAgICAgICBmaQogICAgZG9uZQoKICAgIG9rICJbJFNFUlZFUl9OQU1FXSBDb25maWcgZmlsZXMgc3RhZ2VkICgkY29uZmlnX2NvdW50IGZpbGVzKSIKCiAgICAjIOKUgOKUgCAzLiBDb2xsZWN0IHBhdGhzIHRvIGJhY2sgdXAg4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSACiAgICBsb2NhbCBiYWNrdXBfcGF0aHM9KCIkU1RBR0lOR19ESVIiKQoKICAgIGxvY2FsIHN0b3JhZ2Vfdm9sdW1lPSIkU1VQQUJBU0VfRE9DS0VSX0RJUi92b2x1bWVzL3N0b3JhZ2UiCiAgICBpZiBbIC1kICIkc3RvcmFnZV92b2x1bWUiIF0gJiYgWyAiJChscyAtQSAiJHN0b3JhZ2Vfdm9sdW1lIiAyPi9kZXYvbnVsbCkiIF07IHRoZW4KICAgICAgICBiYWNrdXBfcGF0aHMrPSgiJHN0b3JhZ2Vfdm9sdW1lIikKICAgICAgICBsb2NhbCBzdG9yYWdlX3NpemUKICAgICAgICBzdG9yYWdlX3NpemU9JChkdSAtc2ggIiRzdG9yYWdlX3ZvbHVtZSIgfCBjdXQgLWYxKQogICAgICAgIGluZm8gIlskU0VSVkVSX05BTUVdIEluY2x1ZGluZyBzdG9yYWdlIG9iamVjdHMgKCRzdG9yYWdlX3NpemUpIgogICAgZWxzZQogICAgICAgIHdhcm4gIlskU0VSVkVSX05BTUVdIE5vIHN0b3JhZ2Ugdm9sdW1lIGF0ICRzdG9yYWdlX3ZvbHVtZSDigJQgc2tpcHBpbmciCiAgICBmaQoKICAgICMg4pSA4pSAIDQuIFJ1biByZXN0aWMgYmFja3VwIOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgAogICAgaW5mbyAiWyRTRVJWRVJfTkFNRV0gVXBsb2FkaW5nIHRvICRCQUNLVVBfQkFDS0VORC4uLiIKCiAgICBsb2NhbCByZXN0aWNfb3V0cHV0CiAgICBpZiAhIHJlc3RpY19vdXRwdXQ9JChyZXN0aWMgYmFja3VwIFwKICAgICAgICAtLXRhZyBzdXBhYmFzZSBcCiAgICAgICAgLS10YWcgIiRTRVJWRVJfTkFNRSIgXAogICAgICAgIC0tdGFnICIkKGRhdGUgKyVZJW0lZCkiIFwKICAgICAgICAtLWhvc3QgIiRTRVJWRVJfTkFNRSIgXAogICAgICAgIC0tanNvbiBcCiAgICAgICAgIiR7YmFja3VwX3BhdGhzW0BdfSIgMj4mMSB8IHRhaWwgLTEpOyB0aGVuCgogICAgICAgIGxvY2FsIGVycm1zZz0iUmVzdGljIGJhY2t1cCBmYWlsZWQiCiAgICAgICAgd3JpdGVfc3RhdHVzIGZhbHNlICIkZXJybXNnIgogICAgICAgIG5vdGlmeSAiZmFpbCIgIlskU0VSVkVSX05BTUVdICRlcnJtc2ciCiAgICAgICAgZmFpbCAiWyRTRVJWRVJfTkFNRV0gUmVzdGljIGJhY2t1cCBGQUlMRUQiCiAgICBmaQoKICAgIF9zbmFwc2hvdF9pZD0kKGVjaG8gIiRyZXN0aWNfb3V0cHV0IiB8IGdyZXAgLW8gJyJzbmFwc2hvdF9pZCI6IlteIl0qIicgfCBjdXQgLWQnIicgLWY0IHx8IHRydWUpCiAgICBvayAiWyRTRVJWRVJfTkFNRV0gQmFja3VwIHVwbG9hZGVkIChzbmFwc2hvdDogJHtfc25hcHNob3RfaWQ6LXVua25vd259KSIKCiAgICAjIOKUgOKUgCA1LiBQcnVuZSBvbGQgc25hcHNob3RzIOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgAogICAgaW5mbyAiWyRTRVJWRVJfTkFNRV0gUHJ1bmluZyAoa2VlcDogJHtSRVRFTlRJT05fREFJTFl9ZCAvICR7UkVURU5USU9OX1dFRUtMWX13IC8gJHtSRVRFTlRJT05fTU9OVEhMWX1tKS4uLiIKICAgIHJlc3RpYyBmb3JnZXQgXAogICAgICAgIC0taG9zdCAiJFNFUlZFUl9OQU1FIiBcCiAgICAgICAgLS10YWcgc3VwYWJhc2UgXAogICAgICAgIC0ta2VlcC1kYWlseSAiJFJFVEVOVElPTl9EQUlMWSIgXAogICAgICAgIC0ta2VlcC13ZWVrbHkgIiRSRVRFTlRJT05fV0VFS0xZIiBcCiAgICAgICAgLS1rZWVwLW1vbnRobHkgIiRSRVRFTlRJT05fTU9OVEhMWSIgXAogICAgICAgIC0tcHJ1bmUgMj4mMQoKICAgIGxvY2FsIGVsYXBzZWQ9JCgoICQoZGF0ZSArJXMpIC0gX2JhY2t1cF9zdGFydF90aW1lICkpCiAgICBsb2NhbCBzdW1tYXJ5PSJDb21wbGV0ZWQgaW4gJHtlbGFwc2VkfXMuIERCIGR1bXA6ICR7ZHVtcF9zaXplfS4gQ29uZmlnczogJHtjb25maWdfY291bnR9IGZpbGVzLiIKICAgIHdyaXRlX3N0YXR1cyB0cnVlCiAgICBvayAiWyRTRVJWRVJfTkFNRV0gQmFja3VwIGNvbXBsZXRlICgkc3VtbWFyeSkiCgogICAgbm90aWZ5ICJvayIgIiRzdW1tYXJ5Igp9Cgpkb19saXN0KCkgewogICAgaW5mbyAiWyRTRVJWRVJfTkFNRV0gTGlzdGluZyBzbmFwc2hvdHMuLi4iCiAgICByZXN0aWMgc25hcHNob3RzIC0taG9zdCAiJFNFUlZFUl9OQU1FIiAtLXRhZyBzdXBhYmFzZQp9Cgpkb19zdGF0cygpIHsKICAgIGluZm8gIlskU0VSVkVSX05BTUVdIFJlcG9zaXRvcnkgc3RhdGlzdGljcy4uLiIKICAgIGVjaG8gIiIKICAgIGVjaG8gIiAgU25hcHNob3RzOiIKICAgIHJlc3RpYyBzbmFwc2hvdHMgLS1ob3N0ICIkU0VSVkVSX05BTUUiIC0tdGFnIHN1cGFiYXNlIC0tY29tcGFjdAogICAgZWNobyAiIgogICAgZWNobyAiICBSZXBvc2l0b3J5IHNpemU6IgogICAgcmVzdGljIHN0YXRzIC0tbW9kZSByYXctZGF0YQp9Cgpkb192ZXJpZnkoKSB7CiAgICBpbmZvICJbJFNFUlZFUl9OQU1FXSBWZXJpZnlpbmcgcmVwb3NpdG9yeSBpbnRlZ3JpdHkgKDEwJSBzYW1wbGUpLi4uIgogICAgcmVzdGljIGNoZWNrIC0tcmVhZC1kYXRhLXN1YnNldD0xMCUKICAgIG9rICJbJFNFUlZFUl9OQU1FXSBSZXBvc2l0b3J5IGludGVncml0eSB2ZXJpZmllZCIKfQoKZG9fcmVzdG9yZSgpIHsKICAgIGxvY2FsIHNuYXBzaG90X2lkPSIkezE6LWxhdGVzdH0iCiAgICBsb2NhbCByZXN0b3JlX2Rpcj0iJHsyOi0vdG1wL3N1cGFiYXNlLXJlc3RvcmUtJHtTRVJWRVJfTkFNRX0tJChkYXRlICslcyl9IgoKICAgIGVjaG8gIiIKICAgIGluZm8gIlskU0VSVkVSX05BTUVdIFJlc3RvcmUgcGxhbjoiCiAgICBlY2hvICIgIFNuYXBzaG90OiAgICAkc25hcHNob3RfaWQiCiAgICBlY2hvICIgIFJlc3RvcmUgdG86ICAkcmVzdG9yZV9kaXIiCiAgICBlY2hvICIiCgogICAgaWYgWyAiJHNuYXBzaG90X2lkIiA9ICJsYXRlc3QiIF07IHRoZW4KICAgICAgICBpbmZvICJGZXRjaGluZyBsYXRlc3Qgc25hcHNob3QuLi4iCiAgICAgICAgcmVzdGljIHNuYXBzaG90cyAtLWhvc3QgIiRTRVJWRVJfTkFNRSIgLS10YWcgc3VwYWJhc2UgLS1sYXRlc3QgMQogICAgICAgIGVjaG8gIiIKICAgIGZpCgogICAgcmVhZCAtcnAgIlByb2NlZWQgd2l0aCByZXN0b3JlPyBbeS9OXSAiIGFuc3dlcgogICAgW1sgIiR7YW5zd2VyLCx9IiA9PSAieSIgXV0gfHwgeyBlY2hvICJBYm9ydGVkLiI7IHJldHVybiAwOyB9CgogICAgbWtkaXIgLXAgIiRyZXN0b3JlX2RpciIKICAgIHJlc3RpYyByZXN0b3JlICIkc25hcHNob3RfaWQiIC0taG9zdCAiJFNFUlZFUl9OQU1FIiAtLXRhcmdldCAiJHJlc3RvcmVfZGlyIgoKICAgIG9rICJbJFNFUlZFUl9OQU1FXSBSZXN0b3JlZCB0byAkcmVzdG9yZV9kaXIiCiAgICBlY2hvICIiCiAgICBlY2hvICIgIENvbnRlbnRzOiIKICAgIGxzIC1sYSAiJHJlc3RvcmVfZGlyIi90bXAvc3VwYWJhc2UtYmFja3VwLSovIDI+L2Rldi9udWxsIHx8IGxzIC1sYSAiJHJlc3RvcmVfZGlyIi8KICAgIGVjaG8gIiIKICAgIGVjaG8gIiAgTmV4dCBzdGVwczoiCiAgICBlY2hvICIgIDEuIFJldmlldyBiYWNrdXBfbWV0YWRhdGEuanNvbiB0byBjb25maXJtIHRoaXMgaXMgdGhlIHJpZ2h0IHNlcnZlci9zbmFwc2hvdCIKICAgIGVjaG8gIiAgMi4gUmVzdG9yZSBEQjogICAgIC4vc3VwYWJhc2UtYmFja3VwLnNoIC0tcmVzdG9yZS1kYiAkc25hcHNob3RfaWQiCiAgICBlY2hvICIgIDMuIFJlc3RvcmUgY29uZmlnOiBjb3B5IGZpbGVzIGZyb20gJHJlc3RvcmVfZGlyLy4uLi9jb25maWcvIHRvICRTVVBBQkFTRV9ET0NLRVJfRElSLyIKICAgIGVjaG8gIiAgNC4gUmVzdG9yZSBzdG9yYWdlOiBjb3B5IGZyb20gJHJlc3RvcmVfZGlyLy4uLi9zdG9yYWdlLyB0byAkU1VQQUJBU0VfRE9DS0VSX0RJUi92b2x1bWVzL3N0b3JhZ2UvIgogICAgZWNobyAiIgp9Cgpkb19yZXN0b3JlX2RiKCkgewogICAgbG9jYWwgc25hcHNob3RfaWQ9IiR7MTotbGF0ZXN0fSIKICAgIGxvY2FsIHJlc3RvcmVfZGlyCiAgICByZXN0b3JlX2Rpcj0kKG1rdGVtcCAtZCAvdG1wL3N1cGFiYXNlLWRicmVzdG9yZS0ke1NFUlZFUl9OQU1FfS5YWFhYWFgpCgogICAgaW5mbyAiWyRTRVJWRVJfTkFNRV0gRXh0cmFjdGluZyBkYXRhYmFzZSBkdW1wIGZyb20gc25hcHNob3QgJHNuYXBzaG90X2lkLi4uIgoKICAgICMgUmVzdG9yZSBvbmx5IHRoZSBkdW1wIGZpbGUKICAgIHJlc3RpYyByZXN0b3JlICIkc25hcHNob3RfaWQiIFwKICAgICAgICAtLWhvc3QgIiRTRVJWRVJfTkFNRSIgXAogICAgICAgIC0taW5jbHVkZSAicG9zdGdyZXNfZHVtcC5zcWwuZ3oiIFwKICAgICAgICAtLWluY2x1ZGUgImJhY2t1cF9tZXRhZGF0YS5qc29uIiBcCiAgICAgICAgLS10YXJnZXQgIiRyZXN0b3JlX2RpciIKCiAgICAjIEZpbmQgdGhlIGR1bXAgZmlsZQogICAgbG9jYWwgZHVtcF9maWxlCiAgICBkdW1wX2ZpbGU9JChmaW5kICIkcmVzdG9yZV9kaXIiIC1uYW1lICJwb3N0Z3Jlc19kdW1wLnNxbC5neiIgLXR5cGUgZiB8IGhlYWQgLTEpCgogICAgaWYgWyAteiAiJGR1bXBfZmlsZSIgXTsgdGhlbgogICAgICAgIHJtIC1yZiAiJHJlc3RvcmVfZGlyIgogICAgICAgIGZhaWwgIk5vIHBvc3RncmVzX2R1bXAuc3FsLmd6IGZvdW5kIGluIHNuYXBzaG90ICRzbmFwc2hvdF9pZCIKICAgIGZpCgogICAgIyBTaG93IG1ldGFkYXRhCiAgICBsb2NhbCBtZXRhX2ZpbGUKICAgIG1ldGFfZmlsZT0kKGZpbmQgIiRyZXN0b3JlX2RpciIgLW5hbWUgImJhY2t1cF9tZXRhZGF0YS5qc29uIiAtdHlwZSBmIHwgaGVhZCAtMSkKICAgIGlmIFsgLW4gIiRtZXRhX2ZpbGUiIF07IHRoZW4KICAgICAgICBlY2hvICIiCiAgICAgICAgZWNobyAiICBCYWNrdXAgbWV0YWRhdGE6IgogICAgICAgIGNhdCAiJG1ldGFfZmlsZSIgfCBqcSAuIDI+L2Rldi9udWxsIHx8IGNhdCAiJG1ldGFfZmlsZSIKICAgICAgICBlY2hvICIiCiAgICBmaQoKICAgIGxvY2FsIGR1bXBfc2l6ZQogICAgZHVtcF9zaXplPSQoZHUgLXNoICIkZHVtcF9maWxlIiB8IGN1dCAtZjEpCiAgICBpbmZvICJGb3VuZCBkdW1wOiAkZHVtcF9maWxlICgkZHVtcF9zaXplKSIKCiAgICBlY2hvICIiCiAgICB3YXJuICJUaGlzIHdpbGwgRFJPUCBhbmQgcmVjcmVhdGUgYWxsIGRhdGFiYXNlcyBpbiBjb250YWluZXIgJyRQT1NUR1JFU19DT05UQUlORVInISIKICAgIHJlYWQgLXJwICJBcmUgeW91IGFic29sdXRlbHkgc3VyZT8gVHlwZSAneWVzJyB0byBjb25maXJtOiAiIGFuc3dlcgoKICAgIGlmIFsgIiRhbnN3ZXIiICE9ICJ5ZXMiIF07IHRoZW4KICAgICAgICBlY2hvICJBYm9ydGVkLiBEdW1wIGlzIHN0aWxsIGF2YWlsYWJsZSBhdDogJGR1bXBfZmlsZSIKICAgICAgICByZXR1cm4gMAogICAgZmkKCiAgICBpbmZvICJSZXN0b3JpbmcgZGF0YWJhc2UuLi4iCiAgICBpZiBndW56aXAgPCAiJGR1bXBfZmlsZSIgfCBkb2NrZXIgZXhlYyAtaSAiJFBPU1RHUkVTX0NPTlRBSU5FUiIgcHNxbCAtVSAiJFBPU1RHUkVTX1VTRVIiIDI+JjE7IHRoZW4KICAgICAgICBvayAiWyRTRVJWRVJfTkFNRV0gRGF0YWJhc2UgcmVzdG9yZWQgc3VjY2Vzc2Z1bGx5IgogICAgZWxzZQogICAgICAgIHdhcm4gIlJlc3RvcmUgY29tcGxldGVkIHdpdGggd2FybmluZ3MgKHNvbWUgZXJyb3JzIGFyZSBub3JtYWwgZm9yIHBnX2R1bXBhbGwgLS1jbGVhbikiCiAgICBmaQoKICAgIHJtIC1yZiAiJHJlc3RvcmVfZGlyIgp9Cgpkb19pbnN0YWxsX2Nyb24oKSB7CiAgICBsb2NhbCBjcm9uX3NjaGVkdWxlPSIkezE6LTAgMyAqICogKn0iCiAgICBsb2NhbCBzY3JpcHRfcGF0aAogICAgc2NyaXB0X3BhdGg9JChyZWFkbGluayAtZiAiJDAiKQoKICAgIGxvY2FsIGxvZ19maWxlPSIvdmFyL2xvZy9zdXBhYmFzZS1iYWNrdXAtJHtTRVJWRVJfTkFNRX0ubG9nIgogICAgbG9jYWwgY3Jvbl9pZD0ic3VwYWJhc2UtYmFja3VwLSR7U0VSVkVSX05BTUV9IgogICAgbG9jYWwgY3Jvbl9jbWQ9IiRjcm9uX3NjaGVkdWxlICRzY3JpcHRfcGF0aCAtLW5vdyA+PiAkbG9nX2ZpbGUgMj4mMSAgIyAkY3Jvbl9pZCIKCiAgICAjIENoZWNrIGZvciBleGlzdGluZwogICAgaWYgY3JvbnRhYiAtbCAyPi9kZXYvbnVsbCB8IGdyZXAgLXEgIiRjcm9uX2lkIjsgdGhlbgogICAgICAgIHdhcm4gIkNyb24gYWxyZWFkeSBleGlzdHMgZm9yICckU0VSVkVSX05BTUUnOiIKICAgICAgICBjcm9udGFiIC1sIHwgZ3JlcCAiJGNyb25faWQiCiAgICAgICAgcmVhZCAtcnAgIlJlcGxhY2U/IFt5L05dICIgYW5zd2VyCiAgICAgICAgW1sgIiR7YW5zd2VyLCx9IiA9PSAieSIgXV0gfHwgeyBlY2hvICJLZWVwaW5nIGV4aXN0aW5nLiI7IHJldHVybiAwOyB9CiAgICAgICAgY3JvbnRhYiAtbCAyPi9kZXYvbnVsbCB8IGdyZXAgLXYgIiRjcm9uX2lkIiB8IGNyb250YWIgLQogICAgZmkKCiAgICAoY3JvbnRhYiAtbCAyPi9kZXYvbnVsbDsgZWNobyAiJGNyb25fY21kIikgfCBjcm9udGFiIC0KICAgIG9rICJDcm9uIGluc3RhbGxlZCBmb3IgJyRTRVJWRVJfTkFNRSc6ICRjcm9uX3NjaGVkdWxlIgoKICAgICMgTG9nIHJvdGF0aW9uCiAgICBjYXQgPiAiL2V0Yy9sb2dyb3RhdGUuZC9zdXBhYmFzZS1iYWNrdXAtJHtTRVJWRVJfTkFNRX0iIDw8RU9GCiRsb2dfZmlsZSB7CiAgICB3ZWVrbHkKICAgIHJvdGF0ZSA0CiAgICBjb21wcmVzcwogICAgbWlzc2luZ29rCiAgICBub3RpZmVtcHR5CiAgICBjcmVhdGUgNjQwIHJvb3Qgcm9vdAp9CkVPRgogICAgb2sgIkxvZyByb3RhdGlvbjogJGxvZ19maWxlIgp9Cgpkb191bmluc3RhbGxfY3JvbigpIHsKICAgIGxvY2FsIGNyb25faWQ9InN1cGFiYXNlLWJhY2t1cC0ke1NFUlZFUl9OQU1FfSIKICAgIGlmIGNyb250YWIgLWwgMj4vZGV2L251bGwgfCBncmVwIC1xICIkY3Jvbl9pZCI7IHRoZW4KICAgICAgICBjcm9udGFiIC1sIHwgZ3JlcCAtdiAiJGNyb25faWQiIHwgY3JvbnRhYiAtCiAgICAgICAgb2sgIkNyb24gcmVtb3ZlZCBmb3IgJyRTRVJWRVJfTkFNRSciCiAgICBlbHNlCiAgICAgICAgd2FybiAiTm8gY3JvbiBmb3VuZCBmb3IgJyRTRVJWRVJfTkFNRSciCiAgICBmaQp9Cgpkb190ZXN0X25vdGlmeSgpIHsKICAgIGlmIFsgLXogIiRIRUFMVEhDSEVDS19VUkwiIF07IHRoZW4KICAgICAgICBmYWlsICJIRUFMVEhDSEVDS19VUkwgbm90IHNldCBpbiBiYWNrdXAuZW52IgogICAgZmkKICAgIGluZm8gIlRlc3Rpbmcgbm90aWZpY2F0aW9uICgkSEVBTFRIQ0hFQ0tfTUVUSE9EKS4uLiIKICAgIG5vdGlmeSAib2siICJUZXN0IG5vdGlmaWNhdGlvbiBmcm9tICRTRVJWRVJfTkFNRSBhdCAkKHRzKSIKICAgIG9rICJOb3RpZmljYXRpb24gc2VudCDigJQgY2hlY2sgeW91ciBlbmRwb2ludCIKfQoKIyDilIDilIAgVXNhZ2Ug4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSACnVzYWdlKCkgewogICAgY2F0IDw8RU9GClN1cGFiYXNlIEJhY2t1cCB2MiDigJQgbXVsdGktc2VydmVyIGVkaXRpb24KClNlcnZlcjogICAgICRTRVJWRVJfTkFNRQpSZXBvc2l0b3J5OiAkUkVTVElDX1JFUE9TSVRPUlkKCkNvbW1hbmRzOgogIC0taW5pdCAgICAgICAgICAgICAgSW5pdGlhbGl6ZSByZXN0aWMgcmVwbyBmb3IgdGhpcyBzZXJ2ZXIKICAtLW5vdyAgICAgICAgICAgICAgIFJ1biBiYWNrdXAgbm93CiAgLS1saXN0ICAgICAgICAgICAgICBMaXN0IHNuYXBzaG90cwogIC0tc3RhdHMgICAgICAgICAgICAgU2hvdyByZXBvIHNpemUgYW5kIHNuYXBzaG90IGNvdW50CiAgLS12ZXJpZnkgICAgICAgICAgICBWZXJpZnkgaW50ZWdyaXR5ICgxMCUgc2FtcGxlKQogIC0tcmVzdG9yZSBbU05BUF0gICAgRnVsbCByZXN0b3JlIChkZWZhdWx0OiBsYXRlc3QpCiAgLS1yZXN0b3JlLWRiIFtTTkFQXSBSZXN0b3JlIG9ubHkgZGF0YWJhc2UgKGRlZmF1bHQ6IGxhdGVzdCkKICAtLWluc3RhbGwtY3JvbiAgICAgIEluc3RhbGwgZGFpbHkgM2FtIGNyb24KICAtLXVuaW5zdGFsbC1jcm9uICAgIFJlbW92ZSBjcm9uCiAgLS10ZXN0LW5vdGlmeSAgICAgICBUZXN0IGhlYWx0aC1jaGVjayBub3RpZmljYXRpb24KICAtaCwgLS1oZWxwICAgICAgICAgIFNob3cgdGhpcyBtZXNzYWdlCkVPRgp9CgojIOKUgOKUgCBNYWluIOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgApjYXNlICIkezE6LS0taGVscH0iIGluCiAgICAtLWluaXQpICAgICAgICAgICAgZG9faW5pdCA7OwogICAgLS1ub3cpICAgICAgICAgICAgIGRvX2JhY2t1cCA7OwogICAgLS1saXN0KSAgICAgICAgICAgIGRvX2xpc3QgOzsKICAgIC0tc3RhdHMpICAgICAgICAgICBkb19zdGF0cyA7OwogICAgLS12ZXJpZnkpICAgICAgICAgIGRvX3ZlcmlmeSA7OwogICAgLS1yZXN0b3JlKSAgICAgICAgIGRvX3Jlc3RvcmUgIiR7MjotbGF0ZXN0fSIgIiR7MzotfSIgOzsKICAgIC0tcmVzdG9yZS1kYikgICAgICBkb19yZXN0b3JlX2RiICIkezI6LWxhdGVzdH0iIDs7CiAgICAtLWluc3RhbGwtY3JvbikgICAgZG9faW5zdGFsbF9jcm9uICIkezI6LX0iIDs7CiAgICAtLXVuaW5zdGFsbC1jcm9uKSAgZG9fdW5pbnN0YWxsX2Nyb24gOzsKICAgIC0tdGVzdC1ub3RpZnkpICAgICBkb190ZXN0X25vdGlmeSA7OwogICAgLWh8LS1oZWxwKSAgICAgICAgIHVzYWdlIDs7CiAgICAqKSAgICAgICAgICAgICAgICAgZmFpbCAiVW5rbm93biBjb21tYW5kOiAkMS4gUnVuIHdpdGggLS1oZWxwIiA7Owplc2Fj' | base64 -d > /root/supabase/docker/supabase-backup.sh
chmod +x /root/supabase/docker/supabase-backup.sh

# Write backup config
cat > /root/supabase/docker/backup.env <<BENV
SERVER_NAME="${serverName}"
BACKUP_BACKEND=s3
RESTIC_PASSWORD="${secrets.resticPassword}"
SUPABASE_DOCKER_DIR="/root/supabase/docker"
POSTGRES_CONTAINER="supabase-db"
POSTGRES_USER="postgres"
S3_BUCKET="${s3Bucket}"
S3_ENDPOINT="s3.${s3Region}.amazonaws.com"
AWS_ACCESS_KEY_ID="${s3AccessKey}"
AWS_SECRET_ACCESS_KEY="${s3SecretKey}"
RETENTION_DAILY=7
RETENTION_WEEKLY=4
RETENTION_MONTHLY=6
HEALTHCHECK_URL="${healthcheckUrl || ''}"
HEALTHCHECK_METHOD=simple
BENV
chmod 600 /root/supabase/docker/backup.env

# Init restic repo (S3)
export RESTIC_PASSWORD="${secrets.resticPassword}"
export RESTIC_REPOSITORY="$S3_REPO"
export AWS_ACCESS_KEY_ID="${s3AccessKey}"
export AWS_SECRET_ACCESS_KEY="${s3SecretKey}"
restic init || true

# First backup
update_status "backup_first"
cd /root/supabase/docker
./supabase-backup.sh --now || true

# Cron + log rotation
cd /root/supabase/docker
./supabase-backup.sh --install-cron <<< "n" 2>/dev/null || true
# Fallback: install cron directly
SCRIPT="/root/supabase/docker/supabase-backup.sh"
LOG="/var/log/supabase-backup-${serverName}.log"
(crontab -l 2>/dev/null | grep -v "supabase-backup-${serverName}"; echo "0 3 * * * $SCRIPT --now >> $LOG 2>&1 # supabase-backup-${serverName}") | crontab -

cat > /etc/logrotate.d/supabase-backup-${serverName} <<LOGROT
$LOG {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    create 640 root root
}
LOGROT

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4: MCP SERVER SETUP
# ═══════════════════════════════════════════════════════════════════════════════
update_status "mcp_setup"

# Install Node.js 20 if not already present
if ! command -v node &>/dev/null; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
  apt-get install -y -qq nodejs
fi

MCP_DIR="/home/${deployUser}/mcp-server"
rm -rf "$MCP_DIR"
git clone --depth 1 https://github.com/nadercas/supafast-mcp.git "$MCP_DIR" >/dev/null 2>&1

cd "$MCP_DIR"
npm install --quiet 2>/dev/null || true
npm run build 2>/dev/null || true
npm prune --omit=dev --quiet 2>/dev/null || true

# Write env file for MCP server (only readable by deploy user)
cat > "/home/${deployUser}/.mcp.env" <<MCPENV
SUPABASE_URL="${domain}"
SUPABASE_SERVICE_ROLE_KEY="${secrets.serviceRoleKey}"
SUPABASE_ANON_KEY="${secrets.anonKey}"
SUPABASE_JWT_SECRET="${secrets.jwtSecret}"
SUPABASE_DB_URL="postgresql://postgres.${serverName}:${secrets.postgresPassword}@localhost:5432/postgres"
SUPABASE_FUNCTIONS_DIR="/root/supabase/docker/volumes/functions"
MCPENV
# Allow deploy user to create/update/delete edge functions
chown -R "${deployUser}:${deployUser}" /root/supabase/docker/volumes/functions
chmod 600 "/home/${deployUser}/.mcp.env"
chown "${deployUser}:${deployUser}" "/home/${deployUser}/.mcp.env"

# Create wrapper script that sources env and launches the stdio MCP server
mkdir -p "/home/${deployUser}/bin"
cat > "/home/${deployUser}/bin/supabase-mcp" <<'MCPWRAP'
#!/bin/bash
set -a
source "$HOME/.mcp.env"
set +a
exec node "$HOME/mcp-server/dist/server.js"
MCPWRAP
chmod +x "/home/${deployUser}/bin/supabase-mcp"
chown -R "${deployUser}:${deployUser}" "$MCP_DIR" "/home/${deployUser}/bin"

cd /root/supabase/docker

set -e

# ── SSH Hardening (Phase 2: full lockdown) ──
cat > /etc/ssh/sshd_config.d/99-hardening.conf <<SSHCONF_FINAL
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxSessions 3
LoginGraceTime 30
AllowUsers $DEPLOY_USER
SSHCONF_FINAL
sshd -t && systemctl restart ssh

update_status "complete"

# ── Security cleanup: wipe secrets from memory and logs ──
unset HETZNER_TOKEN
sed -i "s/Bearer [a-zA-Z0-9]*/Bearer REDACTED/g" /var/log/supabase-deploy.log
sed -i "s/HETZNER_TOKEN=\\"[^\\"]*\\"/HETZNER_TOKEN=\\"REDACTED\\"/g" /var/log/supabase-deploy.log
sed -i "s/AWS_ACCESS_KEY_ID=[^ ]*/AWS_ACCESS_KEY_ID=REDACTED/g" /var/log/supabase-deploy.log
sed -i "s/AWS_SECRET_ACCESS_KEY=[^ ]*/AWS_SECRET_ACCESS_KEY=REDACTED/g" /var/log/supabase-deploy.log

echo "DEPLOY_COMPLETED_AT:$(date -Iseconds)"
`;

  // Check if script exceeds 32KB and gzip if needed
  const scriptBytes = new TextEncoder().encode(script);
  if (scriptBytes.length > 32000) {
    // Gzip the entire script and return as base64 — cloud-init auto-detects gzip
    const gzipped = await gzipAndBase64(scriptBytes);
    // cloud-init accepts gzipped user-data with Content-Type or auto-detection
    // Hetzner passes raw user_data, cloud-init detects gzip magic bytes
    // We need to return raw gzipped bytes as the user_data, not base64
    // Actually, Hetzner's API accepts strings, so we use the #cloud-config + write_files approach
    // OR: we can use the mime multipart approach
    // Simplest: return a small bootstrapper that decodes the payload
    return `#!/bin/bash
echo '${gzipped}' | base64 -d | gzip -d | bash
`;
  }

  return script;
}
