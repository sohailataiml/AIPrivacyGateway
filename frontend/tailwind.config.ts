import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        surface: "#0b0f14",
        panel: "#121821",
        edge: "#1e2733",
        ink: "#e6edf3",
        muted: "#8b98a9",
        accent: "#4c9aff",
        protect: "#3fb950",
        warn: "#d29922",
        danger: "#f85149",
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};
export default config;
