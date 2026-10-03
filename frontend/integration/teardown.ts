import { rmSync } from "node:fs";
import type { FullConfig } from "@playwright/test";

export default function teardown(config: FullConfig) {
  rmSync(config.metadata.dataDirectory, { recursive: true, force: true });
}
