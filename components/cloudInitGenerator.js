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
    url: http://studio:3000/api/mcp
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
    _comment: 'MCP: /mcp -> http://studio:3000/api/mcp (local access)'
    url: http://studio:3000/api/mcp
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
    _comment: 'Studio: /* -> http://studio:3000/*'
    url: http://studio:3000/
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
  const { domain } = config;
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
SITE_URL=${domain}
ADDITIONAL_REDIRECT_URLS=
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
ENABLE_EMAIL_AUTOCONFIRM=true
SMTP_ADMIN_EMAIL=admin@example.com
SMTP_HOST=supabase-mail
SMTP_PORT=2500
SMTP_USER=fake_mail_user
SMTP_PASS=fake_mail_password
SMTP_SENDER_NAME=fake_sender
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
`;
}

export function generateDockerCompose(config) {
  const { enableAuthelia, enableRedis } = config;

  // All Docker Compose ${VAR} references are escaped as \${VAR} in JS template literals
  let compose = `name: supabase

services:
  studio:
    container_name: supabase-studio
    image: supabase/studio:2026.01.27-sha-6aa59ff
    restart: unless-stopped
    healthcheck:
      test:
        [
          "CMD",
          "node",
          "-e",
          "fetch('http://studio:3000/api/platform/profile').then((r) => {if (r.status !== 200) throw new Error(r.status)})"
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
      - ./scripts:/app/scripts:ro
      - \${RESTIC_REPOSITORY:-/backups}:/backup
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
      RESTIC_REPOSITORY: /backup
      RESTIC_PASSWORD: \${RESTIC_PASSWORD}`;

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
    reverse_proxy studio:3000
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
    storageBoxUser, storageBoxHost, storageBoxPort, storageBoxPassword,
    healthcheckUrl,
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
  apache2-utils sshpass

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
chmod 600 .env

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
# ── Register pre-generated TOTP secret in Authelia DB ────────────────────────
# The TOTP secret was generated in the browser and shown in the deployer
# credentials page. We insert it directly into Postgres so Authelia recognises
# it immediately — no email, no SMTP, no portal interaction needed.
echo "Registering TOTP secret in Authelia database..."
for i in $(seq 1 24); do
  if docker exec supabase-db pg_isready -U postgres -q 2>/dev/null; then
    echo "Postgres is ready."
    break
  fi
  echo "  attempt $i/24 — waiting 5s..."
  sleep 5
done

# Decode base32 secret to hex, then insert into Authelia's totp_configurations
TOTP_HEX=$(python3 -c "
import base64, sys
s = '${secrets.totpSecret}'
pad = (8 - len(s) % 8) % 8
sys.stdout.write(base64.b32decode(s + '=' * pad, casefold=True).hex())
" 2>/dev/null)

if [ -n "$TOTP_HEX" ]; then
  docker exec supabase-db psql -U postgres -d postgres -c "
    INSERT INTO authelia.totp_configurations
      (username, issuer, algorithm, digits, period, secret)
    VALUES
      ('${supabaseUser}', '${config.domain.replace(/^https?:\/\//, '')}', 'SHA1', 6, 30, decode('$TOTP_HEX', 'hex'))
    ON CONFLICT (username) DO NOTHING;
  " && echo "TOTP registered successfully." || echo "WARNING: TOTP insert failed."
else
  echo "WARNING: Could not decode TOTP secret."
fi
` : ''}
update_status "supabase_done"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: STORAGE BOX + BACKUP SETUP
# ═══════════════════════════════════════════════════════════════════════════════
set +e
update_status "storage_box"

SB_USER="${storageBoxUser}"
SB_HOST="${storageBoxHost}"
SB_PORT="${storageBoxPort}"
SB_ALIAS="storagebox-${serverName}"
SB_KEY="/root/.ssh/storagebox_${serverName}"
SB_CONNECTED=false

# Generate SSH key for Storage Box
mkdir -p /root/.ssh
chmod 700 /root/.ssh
ssh-keygen -t ed25519 -f "$SB_KEY" -N "" -C "backup-${serverName}-$(hostname)"

# Install SSH key on Hetzner Storage Box
if timeout 30 sshpass -p '${storageBoxPassword.replace(/'/g, "'\\''")}' ssh -p "$SB_PORT" \\
  -o StrictHostKeyChecking=accept-new \\
  -o ConnectTimeout=10 \\
  "$SB_USER@$SB_HOST" install-ssh-key < "$SB_KEY.pub" 2>&1; then
  cat >> /root/.ssh/config <<SSHCFG

Host $SB_ALIAS
    HostName $SB_HOST
    User $SB_USER
    Port $SB_PORT
    IdentityFile $SB_KEY
    StrictHostKeyChecking accept-new
SSHCFG
  chmod 600 /root/.ssh/config
  SB_CONNECTED=true
fi

update_status "backup_init"
apt-get install -y -qq restic

# Write the backup script
cat > /root/supabase/docker/supabase-backup.sh <<'BACKUPSCRIPT'
#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
source "\${SCRIPT_DIR}/backup.env"
export RESTIC_PASSWORD
export RESTIC_REPOSITORY

STAGING=$(mktemp -d /tmp/supabase-backup.XXXXXX)
trap 'rm -rf "$STAGING"' EXIT

# Dump postgres
docker exec "\${POSTGRES_CONTAINER:-supabase-db}" pg_dumpall -U "\${POSTGRES_USER:-postgres}" --clean 2>/dev/null | gzip > "$STAGING/postgres_dump.sql.gz"

# Backup metadata
cat > "$STAGING/backup_metadata.json" <<EOJSON
{
    "server_name": "\${SERVER_NAME}",
    "timestamp": "$(date -Iseconds)",
    "postgres_container": "\${POSTGRES_CONTAINER:-supabase-db}",
    "supabase_dir": "\${SUPABASE_DOCKER_DIR}",
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')"
}
EOJSON

# Stage configs
mkdir -p "$STAGING/config"
for f in .env docker-compose.yml volumes/caddy/Caddyfile volumes/authelia/configuration.yml volumes/authelia/users_database.yml; do
  [ -f "\${SUPABASE_DOCKER_DIR}/$f" ] && { mkdir -p "$STAGING/config/$(dirname "$f")"; cp "\${SUPABASE_DOCKER_DIR}/$f" "$STAGING/config/$f"; }
done
for dir in volumes/caddy/snippets; do
  [ -d "\${SUPABASE_DOCKER_DIR}/$dir" ] && { mkdir -p "$STAGING/config/$dir"; cp -r "\${SUPABASE_DOCKER_DIR}/$dir/"* "$STAGING/config/$dir/" 2>/dev/null || true; }
done

# Collect paths
PATHS=("$STAGING")
[ -d "\${SUPABASE_DOCKER_DIR}/volumes/storage" ] && PATHS+=("\${SUPABASE_DOCKER_DIR}/volumes/storage")

# Backup
restic backup --tag supabase --tag "\${SERVER_NAME}" --host "\${SERVER_NAME}" "\${PATHS[@]}"

# Prune
restic forget --host "\${SERVER_NAME}" --tag supabase \\
  --keep-daily "\${RETENTION_DAILY:-7}" --keep-weekly "\${RETENTION_WEEKLY:-4}" \\
  --keep-monthly "\${RETENTION_MONTHLY:-6}" --prune

# Health-check notification
if [ -n "\${HEALTHCHECK_URL:-}" ]; then
  curl -fsS -m 10 --retry 3 "\${HEALTHCHECK_URL}" >/dev/null 2>&1 || true
fi
BACKUPSCRIPT
chmod +x /root/supabase/docker/supabase-backup.sh

# Write backup config
if [ "$SB_CONNECTED" = true ]; then
  REPO="sftp:$SB_USER@$SB_ALIAS:/backups/${serverName}"
else
  mkdir -p "/root/backups/${serverName}"
  REPO="/root/backups/${serverName}"
fi

cat > /root/supabase/docker/backup.env <<BENV
SERVER_NAME="${serverName}"
RESTIC_PASSWORD="${secrets.resticPassword}"
SUPABASE_DOCKER_DIR="/root/supabase/docker"
POSTGRES_CONTAINER="supabase-db"
POSTGRES_USER="postgres"
RESTIC_REPOSITORY="$REPO"
RETENTION_DAILY=7
RETENTION_WEEKLY=4
RETENTION_MONTHLY=6
HEALTHCHECK_URL="${healthcheckUrl || ''}"
BENV
chmod 600 /root/supabase/docker/backup.env

# Init restic repo
export RESTIC_PASSWORD="${secrets.resticPassword}"
export RESTIC_REPOSITORY="$REPO"
restic init || true

# First backup
update_status "backup_first"
cd /root/supabase/docker
./supabase-backup.sh || true

# Cron + log rotation
SCRIPT="/root/supabase/docker/supabase-backup.sh"
LOG="/var/log/supabase-backup-${serverName}.log"
(crontab -l 2>/dev/null; echo "0 3 * * * $SCRIPT >> $LOG 2>&1 # supabase-backup-${serverName}") | crontab -

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
sed -i "s/sshpass -p '[^']*'/sshpass -p 'REDACTED'/g" /var/log/supabase-deploy.log

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
