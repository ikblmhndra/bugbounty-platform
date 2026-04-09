/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx}",
    "./components/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bg: {
          primary:   "#050705",
          secondary: "#0a120a",
          tertiary:  "#112011",
        },
        border: "#1f3a1f",
        accent: {
          DEFAULT: "#39ff14",
          hover:   "#6bff4f",
        },
        sev: {
          critical: "#ff4444",
          high:     "#ff8c00",
          medium:   "#ffd700",
          low:      "#3fb950",
          info:     "#8b949e",
        },
        text: {
          primary:   "#d4ffd0",
          secondary: "#8fbc8f",
          muted:     "#5c7a5c",
        },
      },
      fontFamily: {
        mono: ["'JetBrains Mono'", "monospace"],
        sans: ["'Inter'", "system-ui", "sans-serif"],
      },
    },
  },
  plugins: [],
};
