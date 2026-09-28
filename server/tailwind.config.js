module.exports = {
  content: ["./templates/**/*.html"],
  theme: {
    extend: {
      colors: {
        // Dark, technical/ops-tool surface scale — darkest to lightest.
        base: {
          950: "#080B0F",
          900: "#0B0F14",
          850: "#0F141A",
          800: "#131920",
          750: "#171E26",
          700: "#1C232D",
          600: "#232B36",
          500: "#2E3846",
          400: "#3D4B5C",
        },
        ink: {
          100: "#E6E9EF",
          300: "#C4CBD4",
          500: "#9AA5B1",
          700: "#667080",
        },
        // Single brand accent — deliberately not indigo/purple/blue, so it
        // doesn't collide semantically with status colors below.
        accent: {
          400: "#22D3EE",
          500: "#06B6D4",
          600: "#0891B2",
        },
        status: {
          online: "#34D399",
          offline: "#667080",
          warning: "#FBBF24",
          critical: "#F87171",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      boxShadow: {
        // Dark-mode elevation: box-shadow alone is nearly invisible on a
        // dark background, so pair a soft outer glow with a real shadow.
        card: "0 0 0 1px rgba(255,255,255,0.04), 0 4px 16px rgba(0,0,0,0.35)",
        panel: "0 0 0 1px rgba(255,255,255,0.06), 0 12px 40px rgba(0,0,0,0.5)",
      },
      transitionDuration: {
        150: "150ms",
      },
    },
  },
  plugins: [],
};
