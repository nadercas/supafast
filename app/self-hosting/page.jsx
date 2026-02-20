"use client";
import Link from "next/link";

const C = {
  bg: "#0a0a0d",
  surface: "#111115",
  surfaceAlt: "#16161c",
  border: "#1e1e26",
  text: "#e8e8f0",
  muted: "#9090a8",
  dim: "#555568",
  green: "#3ecf8e",
  greenDark: "#1a9f60",
};

const mono = "'JetBrains Mono', 'SF Mono', 'Fira Code', monospace";

function Code({ children, block = false }) {
  if (block) {
    return (
      <pre style={{
        background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8,
        padding: "16px 20px", fontSize: 12, color: C.text, overflowX: "auto",
        fontFamily: mono, lineHeight: 1.7, margin: "12px 0",
      }}>
        {children}
      </pre>
    );
  }
  return (
    <code style={{
      background: C.surfaceAlt, border: `1px solid ${C.border}`,
      borderRadius: 4, padding: "1px 6px", fontSize: 12, color: C.green, fontFamily: mono,
    }}>
      {children}
    </code>
  );
}

function Section({ title, children }) {
  return (
    <section style={{ marginBottom: 48 }}>
      <h2 style={{ fontSize: 16, fontWeight: 700, color: C.text, margin: "0 0 16px", paddingBottom: 10, borderBottom: `1px solid ${C.border}`, fontFamily: mono }}>
        {title}
      </h2>
      {children}
    </section>
  );
}

function Step({ n, title, children }) {
  return (
    <div style={{ display: "flex", gap: 16, marginBottom: 24 }}>
      <div style={{
        width: 28, height: 28, borderRadius: "50%", flexShrink: 0,
        background: `linear-gradient(135deg, ${C.green}, ${C.greenDark})`,
        display: "flex", alignItems: "center", justifyContent: "center",
        fontSize: 12, fontWeight: 800, color: "#000", fontFamily: mono, marginTop: 2,
      }}>{n}</div>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 6, fontFamily: mono }}>{title}</div>
        <div style={{ fontSize: 12, color: C.muted, lineHeight: 1.8, fontFamily: mono }}>{children}</div>
      </div>
    </div>
  );
}

function Note({ children }) {
  return (
    <div style={{
      background: "#0c1a14", border: `1px solid #1a3a28`, borderRadius: 8,
      padding: "12px 16px", fontSize: 12, color: C.muted, lineHeight: 1.7,
      fontFamily: mono, margin: "12px 0",
    }}>
      <span style={{ color: C.green, fontWeight: 700 }}>Note: </span>{children}
    </div>
  );
}

export default function SelfHostingPage() {
  return (
    <div style={{ minHeight: "100vh", background: C.bg, color: C.text, fontFamily: mono }}>
      {/* Header */}
      <header style={{
        borderBottom: `1px solid ${C.border}`, padding: "14px 24px",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        background: `linear-gradient(180deg, #0f0f12, ${C.bg})`,
      }}>
        <Link href="/" style={{ display: "flex", alignItems: "center", gap: 10, textDecoration: "none" }}>
          <div style={{
            width: 30, height: 30, borderRadius: 7,
            background: `linear-gradient(135deg, ${C.green}, ${C.greenDark})`,
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 15, fontWeight: 800, color: "#000",
          }}>S</div>
          <span style={{ fontSize: 14, fontWeight: 600, color: C.text }}>
            supabase<span style={{ color: C.green }}>:</span><span style={{ color: C.green }}>:</span>deploy
          </span>
        </Link>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Link href="/" style={{ fontSize: 11, color: C.dim, textDecoration: "none", padding: "4px 10px", borderRadius: 6, border: `1px solid ${C.border}`, background: C.surface }}>
            ← Back to Deployer
          </Link>
          <a href="https://github.com/nadercas/supafast" target="_blank" rel="noopener noreferrer"
            style={{ fontSize: 11, color: C.dim, textDecoration: "none", padding: "4px 10px", borderRadius: 6, border: `1px solid ${C.border}`, background: C.surface, display: "flex", alignItems: "center", gap: 6 }}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/></svg>
            GitHub
          </a>
        </div>
      </header>

      {/* Content */}
      <div style={{ maxWidth: 780, margin: "0 auto", padding: "48px 24px 80px" }}>
        <div style={{ marginBottom: 48 }}>
          <h1 style={{
            fontSize: 28, fontWeight: 700, margin: "0 0 12px",
            background: `linear-gradient(135deg, ${C.text} 30%, ${C.green})`,
            WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
          }}>
            Self-Hosting SupaFast
          </h1>
          <p style={{ fontSize: 13, color: C.muted, margin: 0, lineHeight: 1.8 }}>
            SupaFast is a Next.js app that runs entirely in the browser — there is no backend, no database, no server state.
            All secrets are generated client-side. You can fork it, self-host it on Vercel, Netlify, or any static host, and it will work identically.
          </p>
        </div>

        <Section title="Prerequisites">
          <div style={{ fontSize: 12, color: C.muted, lineHeight: 2 }}>
            • Node.js 18+ and npm<br />
            • Git<br />
            • A Vercel / Netlify account — or any host that supports Next.js static export<br />
            • (Optional) A custom domain
          </div>
        </Section>

        <Section title="Quick Deploy — Vercel (Recommended)">
          <Step n="1" title="Fork the repo">
            Go to{" "}
            <a href="https://github.com/nadercas/supafast" target="_blank" rel="noopener noreferrer" style={{ color: C.green }}>
              github.com/nadercas/supafast
            </a>{" "}
            and click <strong style={{ color: C.text }}>Fork</strong>. This gives you your own copy to deploy from.
          </Step>
          <Step n="2" title="Import to Vercel">
            Go to{" "}
            <a href="https://vercel.com/new" target="_blank" rel="noopener noreferrer" style={{ color: C.green }}>vercel.com/new</a>,
            click <strong style={{ color: C.text }}>Import Git Repository</strong>, and select your fork.
            Vercel auto-detects Next.js — no configuration needed.
          </Step>
          <Step n="3" title="Deploy">
            Click <strong style={{ color: C.text }}>Deploy</strong>. Done. Vercel gives you a <Code>*.vercel.app</Code> URL immediately.
            You can add a custom domain in project settings.
          </Step>
          <Note>No environment variables are required. The app has zero server-side dependencies.</Note>
        </Section>

        <Section title="Run Locally">
          <Code block>{`git clone https://github.com/nadercas/supafast.git
cd supafast
npm install
npm run dev`}</Code>
          <p style={{ fontSize: 12, color: C.muted, margin: "8px 0 0" }}>
            Open <Code>http://localhost:3000</Code>. The deployer is fully functional locally — it calls the Hetzner API directly from your browser.
          </p>
        </Section>

        <Section title="Deploy to Netlify">
          <Step n="1" title="Fork the repo">
            Fork{" "}
            <a href="https://github.com/nadercas/supafast" target="_blank" rel="noopener noreferrer" style={{ color: C.green }}>
              github.com/nadercas/supafast
            </a>{" "}
            to your GitHub account.
          </Step>
          <Step n="2" title="Connect to Netlify">
            Go to <a href="https://app.netlify.com" target="_blank" rel="noopener noreferrer" style={{ color: C.green }}>app.netlify.com</a> → <strong style={{ color: C.text }}>Add new site → Import an existing project</strong> → select your fork.
          </Step>
          <Step n="3" title="Configure build settings">
            Netlify should auto-detect these. If not, set manually:
            <Code block>{`Build command:  npm run build
Publish directory: .next`}</Code>
          </Step>
          <Step n="4" title="Deploy">
            Click <strong style={{ color: C.text }}>Deploy site</strong>. Netlify gives you a <Code>*.netlify.app</Code> URL.
          </Step>
        </Section>

        <Section title="Self-Host on a VPS (Docker)">
          <p style={{ fontSize: 12, color: C.muted, margin: "0 0 16px" }}>
            If you want to run it on your own server rather than a managed platform:
          </p>
          <Code block>{`# Clone your fork
git clone https://github.com/YOUR_USERNAME/supafast.git
cd supafast

# Build
npm install
npm run build

# Run with Node
npm start
# Now serving on http://localhost:3000

# Or run with PM2 for persistence
npm install -g pm2
pm2 start npm --name supafast -- start
pm2 save`}</Code>
          <p style={{ fontSize: 12, color: C.muted, margin: "12px 0 0" }}>
            Put Nginx or Caddy in front for HTTPS. Example Caddyfile:
          </p>
          <Code block>{`yourdomain.com {
    reverse_proxy localhost:3000
}`}</Code>
        </Section>

        <Section title="Customization">
          <div style={{ fontSize: 12, color: C.muted, lineHeight: 2 }}>
            The two files you'll most likely want to edit:
          </div>
          <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 8 }}>
            {[
              ["components/SupabaseDeployer.jsx", "Main UI — wizard steps, styling, server type catalog, Hetzner API client"],
              ["components/cloudInitGenerator.js", "The cloud-init bash script that runs on the server at first boot — backup, Authelia, Caddy, MCP, etc."],
              ["management/server.js", "Management panel backend (Node.js) — runs inside a Docker container on your deployed server"],
              ["management/public/index.html", "Management panel frontend — dashboard, backup status, logs, restore instructions"],
            ].map(([file, desc]) => (
              <div key={file} style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: "12px 16px" }}>
                <div style={{ fontSize: 12, color: C.green, marginBottom: 4 }}>{file}</div>
                <div style={{ fontSize: 11, color: C.dim }}>{desc}</div>
              </div>
            ))}
          </div>
        </Section>

        <Section title="Architecture">
          <p style={{ fontSize: 12, color: C.muted, lineHeight: 1.8, margin: "0 0 16px" }}>
            SupaFast has a zero-backend architecture. Here's the complete data flow:
          </p>
          <Code block>{`Browser (your machine)
  │
  ├── Generates all secrets via Web Crypto API (never leaves browser)
  ├── Calls api.hetzner.cloud directly (your token, your API, no proxy)
  ├── Generates a cloud-init bash script (all secrets embedded)
  └── Passes cloud-init as user_data when creating the Hetzner server
                              │
                              ▼
              Hetzner Server (first boot)
                              │
              cloud-init runs the bash script:
              ├── Phase 1: OS hardening
              ├── Phase 2: Supabase docker stack
              ├── Phase 3: Restic backups to S3
              ├── Phase 4: Management dashboard container
              └── Phase 5: MCP server (Claude/Cursor integration)`}</Code>
          <Note>
            SupaFast itself never sees your Hetzner token, Supabase secrets, or S3 credentials.
            All API calls are visible in your browser's Network tab.
          </Note>
        </Section>

        <Section title="Keeping Up to Date">
          <p style={{ fontSize: 12, color: C.muted, lineHeight: 1.8, margin: "0 0 12px" }}>
            If you forked the repo and want to pull upstream changes:
          </p>
          <Code block>{`# Add the upstream remote (one-time)
git remote add upstream https://github.com/nadercas/supafast.git

# Pull updates
git fetch upstream
git merge upstream/main

# Redeploy (Vercel/Netlify auto-deploys on push to main)
git push origin main`}</Code>
        </Section>

        <div style={{ paddingTop: 32, borderTop: `1px solid ${C.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ fontSize: 11, color: C.dim }}>
            MIT License ·{" "}
            <a href="https://github.com/nadercas/supafast" target="_blank" rel="noopener noreferrer" style={{ color: C.muted, textDecoration: "none" }}>
              github.com/nadercas/supafast
            </a>
          </div>
          <Link href="/" style={{
            fontSize: 12, padding: "8px 16px", borderRadius: 6, textDecoration: "none",
            background: `linear-gradient(135deg, ${C.green}, ${C.greenDark})`,
            color: "#000", fontWeight: 700,
          }}>
            Launch Deployer →
          </Link>
        </div>
      </div>
    </div>
  );
}
