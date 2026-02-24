import { ImageResponse } from "next/og";

export const runtime = "edge";

export async function GET() {
  const response = new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          background: "#0a0a0d",
          padding: "60px 70px",
          fontFamily: "monospace",
          position: "relative",
        }}
      >
        {/* Grid pattern background */}
        <div
          style={{
            position: "absolute",
            inset: 0,
            backgroundImage:
              "linear-gradient(rgba(62,207,142,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(62,207,142,0.04) 1px, transparent 1px)",
            backgroundSize: "40px 40px",
          }}
        />

        {/* Top glow */}
        <div
          style={{
            position: "absolute",
            top: -100,
            left: "50%",
            width: 600,
            height: 300,
            background: "radial-gradient(ellipse, rgba(62,207,142,0.12) 0%, transparent 70%)",
            transform: "translateX(-50%)",
          }}
        />

        {/* Logo + name row */}
        <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 48 }}>
          <div
            style={{
              width: 52,
              height: 52,
              borderRadius: 12,
              background: "linear-gradient(135deg, #3ecf8e, #1a9f60)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 26,
              fontWeight: 800,
              color: "#000",
            }}
          >
            S
          </div>
          <span style={{ fontSize: 22, fontWeight: 600, color: "#e8e8f0", letterSpacing: "0.02em" }}>
            supabase
            <span style={{ color: "#3ecf8e" }}>:</span>
            <span style={{ color: "#3ecf8e" }}>:</span>
            deploy
          </span>
        </div>

        {/* Main headline */}
        <div
          style={{
            fontSize: 56,
            fontWeight: 800,
            color: "#e8e8f0",
            lineHeight: 1.15,
            marginBottom: 24,
            maxWidth: 840,
          }}
        >
          Self-Host Supabase{" "}
          <span style={{ color: "#3ecf8e" }}>in 10 minutes.</span>
        </div>

        {/* Subtitle */}
        <div style={{ fontSize: 22, color: "#9090a8", lineHeight: 1.6, marginBottom: 48, maxWidth: 760 }}>
          Production-hardened deployment with encrypted backups, 2FA, and full Claude MCP integration. All secrets stay in your browser.
        </div>

        {/* Feature pills */}
        <div style={{ display: "flex", gap: 12 }}>
          {["Zero-Knowledge", "Encrypted Backups", "2FA · Authelia", "Claude MCP"].map((label) => (
            <div
              key={label}
              style={{
                background: "#111115",
                border: "1px solid #1e1e26",
                borderRadius: 8,
                padding: "8px 16px",
                fontSize: 14,
                color: "#9090a8",
                display: "flex",
                alignItems: "center",
                gap: 6,
              }}
            >
              <div
                style={{
                  width: 6,
                  height: 6,
                  borderRadius: "50%",
                  background: "#3ecf8e",
                }}
              />
              {label}
            </div>
          ))}
        </div>

        {/* Bottom right — URL */}
        <div
          style={{
            position: "absolute",
            bottom: 52,
            right: 70,
            fontSize: 16,
            color: "#555568",
          }}
        >
          supafast.site
        </div>
      </div>
    ),
    {
      width: 1200,
      height: 630,
    }
  );
  response.headers.set("Cache-Control", "public, max-age=86400, immutable");
  return response;
}
