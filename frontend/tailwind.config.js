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
          primary:   "#0d1117",
          secondary: "#161b22",
          tertiary:  "#21262d",
        },
        border: "#30363d",
        accent: {
          DEFAULT: "#58a6ff",
          hover:   "#79b8ff",
        },
        sev: {
          critical: "#ff4444",
          high:     "#ff8c00",
          medium:   "#ffd700",
          low:      "#3fb950",
          info:     "#8b949e",
        },
        text: {
          primary:   "#c9d1d9",
          secondary: "#8b949e",
          muted:     "#484f58",
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
