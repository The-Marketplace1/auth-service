import { defineConfig } from "orval";
import path from "node:path";

const root = path.resolve(__dirname, "..");

export default defineConfig({
  zod: {
    input: {
      target: path.resolve(root, "docs/openapi.yaml"),
    },
    output: {
      workspace: path.resolve(root, "src/validation"),
      target: "generated",
      client: "zod",
      mode: "split",
      schemas: { path: "generated/types", type: "typescript" },
      clean: true,
      prettier: true,
      override: {
        zod: {
          coerce: {
            query: ["boolean", "number", "string"],
            param: ["boolean", "number", "string"],
            body: ["bigint", "date"],
            response: ["bigint", "date"],
          },
        },
        useDates: true,
        useBigInt: true,
      },
    },
  },
});

