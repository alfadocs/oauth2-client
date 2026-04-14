import { copyFile, mkdir, readdir } from "node:fs/promises";

const sourceDir = new URL("../src/supabase-bridge/migrations/", import.meta.url);
const targetDir = new URL("../dist/supabase-bridge/migrations/", import.meta.url);

await mkdir(targetDir, { recursive: true });
const files = await readdir(sourceDir);

for (const fileName of files) {
  await copyFile(new URL(fileName, sourceDir), new URL(fileName, targetDir));
}
