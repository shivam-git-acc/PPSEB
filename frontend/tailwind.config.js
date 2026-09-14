/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#0a0d12",
          900: "#10141b",
          850: "#141924",
          800: "#1a2029",
          700: "#242c38",
          600: "#333d4d",
          500: "#4a5568",
          400: "#6b7788",
          300: "#94a1b3",
          200: "#c2ccd9",
          100: "#e4e9f0",
        },
        amber: {
          400: "#f2b544",
          500: "#e0a030",
          600: "#c2841e",
        },
        signal: {
          green: "#3ecf8e",
          red: "#f2685c",
          blue: "#5b9dee",
        },
      },
      fontFamily: {
        mono: [
          "ui-monospace", "SFMono-Regular", "JetBrains Mono", "Menlo",
          "Consolas", "Liberation Mono", "monospace",
        ],
        sans: [
          "Inter", "ui-sans-serif", "system-ui", "-apple-system",
          "Segoe UI", "Roboto", "sans-serif",
        ],
      },
    },
  },
  plugins: [],
};
