import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build as esbuild } from "esbuild";
import esbuildPluginPino from "esbuild-plugin-pino";
import { rm } from "node:fs/promises";

globalThis.require = createRequire(import.meta.url);

const root = path.dirname(fileURLToPath(import.meta.url));

await rm(path.resolve(root, "dist"), { recursive: true, force: true });

await esbuild({
  entryPoints: [path.resolve(root, "src/app/index.ts")],
  platform: "node",
  bundle: true,
  format: "esm",
  outdir: path.resolve(root, "dist"),
  outExtension: { ".js": ".mjs" },
  sourcemap: "linked",
  external: [
    "*.node",
    "bcrypt",
    "argon2",
    "fsevents",
    "pg-native",
    "nodemailer",
    "sharp",
    "canvas",
    "playwright",
    "puppeteer",
  ],
  plugins: [esbuildPluginPino({ transports: ["pino-pretty"] })],
  banner: {
    js: `import { createRequire as __bannerCrReq } from 'node:module';
import __bannerPath from 'node:path';
import __bannerUrl from 'node:url';

globalThis.require = __bannerCrReq(import.meta.url);
globalThis.__filename = __bannerUrl.fileURLToPath(import.meta.url);
globalThis.__dirname = __bannerPath.dirname(globalThis.__filename);
    `,
  },
});
