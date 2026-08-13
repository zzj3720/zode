import { existsSync, realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig, searchForWorkspaceRoot } from "vite-plus";

const webRoot = dirname(fileURLToPath(import.meta.url));
const nodeModulesPath = resolve(webRoot, "node_modules");
const allowedFsRoots = [searchForWorkspaceRoot(webRoot)];
if (existsSync(nodeModulesPath)) {
  allowedFsRoots.push(realpathSync(nodeModulesPath));
}

const devApiTarget =
  (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env
    ?.ZODE_DEV_API_ORIGIN ?? "http://127.0.0.1:60903";

export default defineConfig({
  server: {
    host: true,
    fs: {
      allow: allowedFsRoots,
    },
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
    ignorePatterns: ["dist/**", "node_modules/**", "e2e/**", "AGENTS.md", "vite.config.ts"],
    options: {
      typeAware: true,
      typeCheck: true,
    },
  },
});
