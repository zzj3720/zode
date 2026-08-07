import { defineConfig } from "vite-plus";

export default defineConfig({
  staged: {
    "*": "vp check --fix",
  },
  build: {
    outDir: "dist",
  },
  fmt: {
    ignorePatterns: ["dist/**", "node_modules/**", "e2e/**", "AGENTS.md"],
  },
  lint: {
    ignorePatterns: ["dist/**", "node_modules/**", "e2e/**", "AGENTS.md"],
    options: {
      typeAware: true,
      typeCheck: true,
    },
  },
});
