// eslint-config-next 16 ships a flat config array directly, so it is spread
// rather than wrapped in FlatCompat -- the compat shim chokes on it.
import next from "eslint-config-next";

const config = [
  { ignores: [".next/**", "node_modules/**", "next-env.d.ts"] },
  ...next,
];

export default config;
