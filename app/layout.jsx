export const metadata = {
  metadataBase: new URL("https://supafast.site"),
  title: "SupaFast — Self-Host Supabase in 10 Minutes",
  description:
    "Production-hardened Supabase deployment with encrypted S3 backups, Authelia 2FA, and Claude MCP integration. Zero-knowledge — all secrets generated in your browser.",
  keywords: "Supabase, self-hosted, Hetzner, deployment, zero-knowledge, backup, security, MCP, Claude",
  authors: [{ name: "SupaFast", url: "https://github.com/nadercas/supafast" }],
  openGraph: {
    title: "SupaFast — Self-Host Supabase in 10 Minutes",
    description:
      "Production-hardened Supabase deployment with encrypted S3 backups, Authelia 2FA, and Claude MCP integration. All secrets stay in your browser.",
    url: "https://supafast.site",
    siteName: "SupaFast",
    images: [
      {
        url: "/api/og",
        width: 1200,
        height: 630,
        alt: "SupaFast — Self-Host Supabase in 10 Minutes",
      },
    ],
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "SupaFast — Self-Host Supabase in 10 Minutes",
    description:
      "Production-hardened Supabase deployment with encrypted S3 backups, Authelia 2FA, and Claude MCP integration. All secrets stay in your browser.",
    images: ["/api/og"],
    creator: "@nadercas",
  },
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body style={{ margin: 0, padding: 0 }}>{children}</body>
    </html>
  );
}
