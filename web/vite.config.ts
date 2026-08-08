import { defineConfig } from "vite-plus";

export default defineConfig({
  staged: {
    "*": "vp check --fix",
  },
  build: {
    outDir: "dist",
    rollupOptions: {
      output: {
        entryFileNames: "assets/[name]-[hash:12].js",
        chunkFileNames: "assets/[name]-[hash:12].js",
        assetFileNames: "assets/[name]-[hash:12][extname]",
      },
    },
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
