import { defineConfig } from "vite-plus";

const devApiTarget =
  (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env
    ?.ZODE_DEV_API_ORIGIN ?? "http://127.0.0.1:60903";

export default defineConfig({
  server: {
    host: true,
    proxy: {
      "/v1": {
        target: devApiTarget,
        changeOrigin: false,
      },
    },
  },
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
