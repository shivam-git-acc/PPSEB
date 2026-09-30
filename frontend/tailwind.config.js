/** @type {import('tailwindcss').Config} */

// Palette validated with the dataviz skill's checker against the panel surface
// #101219 (dark):
//   categorical  #3987e5 / #d95926 / #199e70  -> ALL CHECKS PASS under --pairs all
//   status       good #0ca30c, warning #fab219, critical #d03b3b
//                -> red<->green CVD dE 4.1 (deutan), so a status colour NEVER
//                   carries meaning alone: every one is paired with a text
//                   label, a shape, or an axis position. See index.css.
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        // Surfaces and ink, deepest -> brightest.
        ink: {
          975: "#07080c",   // app plane
          950: "#0a0c11",   // page
          900: "#101219",   // panel  (the validated chart surface)
          850: "#141721",   // raised
          800: "#1f2430",   // hairline border
          700: "#2a3040",   // border
          600: "#3a4356",   // disabled / faint rule
          500: "#6f7a8d",   // muted ink: axis ticks, captions
          400: "#8b95a8",
          300: "#a4aec0",   // secondary ink: body
          200: "#ccd4e0",
          100: "#e8ecf4",   // primary ink: headings, values
        },
        // Chrome accent. Deliberately not a series hue, so UI furniture never
        // impersonates a data mark.
        accent: {
          DEFAULT: "#6e8cff",
          soft: "#8ba3ff",
          dim: "#3d4c8f",
        },
        // Categorical series, in fixed order. Never cycled, never reassigned
        // by rank.
        series: {
          1: "#3987e5",
          2: "#d95926",
          3: "#199e70",
        },
        // Status. Reserved: never reused as "series 4".
        signal: {
          green: "#0ca30c",
          red: "#d03b3b",
          blue: "#3987e5",
          amber: "#fab219",
        },
        amber: { 400: "#fab219", 500: "#d99a10", 600: "#a8760a" },
        chart: { grid: "#1a1f29", axis: "#2b3241" },
      },
      fontFamily: {
        sans: ['"Inter var"', "Inter", "ui-sans-serif", "system-ui", "-apple-system",
               '"Segoe UI"', "Roboto", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", '"JetBrains Mono"', '"Cascadia Mono"',
               "Menlo", "Consolas", '"Liberation Mono"', "monospace"],
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem", letterSpacing: "0.01em" }],
      },
      borderRadius: { xl2: "0.875rem" },
      boxShadow: {
        panel: "0 1px 0 0 rgba(255,255,255,0.04) inset, 0 8px 24px -12px rgba(0,0,0,0.7)",
        pop: "0 16px 48px -12px rgba(0,0,0,0.8), 0 0 0 1px rgba(255,255,255,0.06)",
      },
    },
  },
  plugins: [],
};
