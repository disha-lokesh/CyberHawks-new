/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0a0a0f",
        surface: "#0f0f1a",
        border: "#1a1a2e",
        crimson: "#e94560",
        cyan: "#00d4ff",
        neon: "#00ff88",
        amber: "#f39c12",
        alarm: "#ff2244",
        ink: "#e8e8f0",
        muted: "#6b6b8a",
        tier: {
          benign: "#00ff88",
          suspicious: "#f39c12",
          high: "#e67e22",
          critical: "#ff2244",
        },
      },
      fontFamily: {
        mono: [
          "'JetBrains Mono'", "'Fira Code'", "ui-monospace", "'SF Mono'",
          "'Cascadia Code'", "Consolas", "monospace",
        ],
        sans: [
          "Inter", "'Space Grotesk'", "-apple-system", "'Segoe UI'",
          "Roboto", "sans-serif",
        ],
      },
      boxShadow: {
        glowCrimson: "0 0 12px rgba(233,69,96,0.55)",
        glowCyan: "0 0 12px rgba(0,212,255,0.55)",
        glowGreen: "0 0 12px rgba(0,255,136,0.55)",
        glowAlarm: "0 0 18px rgba(255,34,68,0.75)",
      },
      keyframes: {
        pulseBorder: {
          "0%, 100%": { boxShadow: "0 0 0px rgba(255,34,68,0)" },
          "50%": { boxShadow: "0 0 24px rgba(255,34,68,0.85)" },
        },
        scanline: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100%)" },
        },
        blinkCursor: {
          "0%, 49%": { opacity: 1 },
          "50%, 100%": { opacity: 0 },
        },
        ripple: {
          "0%": { transform: "scale(0)", opacity: 0.6 },
          "100%": { transform: "scale(3)", opacity: 0 },
        },
      },
      animation: {
        pulseBorder: "pulseBorder 2s ease-in-out infinite",
        scanline: "scanline 3s linear infinite",
        blinkCursor: "blinkCursor 1s step-start infinite",
        ripple: "ripple 0.8s ease-out forwards",
      },
    },
  },
  plugins: [],
};
