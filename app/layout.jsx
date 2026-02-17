export const metadata = {
  title: 'Supabase Deploy - Zero-Knowledge Deployment to Hetzner',
  description: 'Deploy production-ready Supabase to Hetzner Cloud with automated hardening, 2FA, and encrypted backups. Zero-knowledge architecture - all secrets stay in your browser.',
  keywords: 'Supabase, Hetzner, deployment, self-hosted, zero-knowledge, backup, security',
  authors: [{ name: 'Supabase Deploy' }],
  openGraph: {
    title: 'Supabase Deploy - Zero-Knowledge Deployment',
    description: 'Deploy production-ready Supabase in 10 minutes with automated hardening and encrypted backups',
    type: 'website',
  },
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet" />
      </head>
      <body style={{ margin: 0, padding: 0 }}>
        {children}
      </body>
    </html>
  )
}
