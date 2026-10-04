import { spawn } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { delimiter, join } from "node:path";
import { StringDecoder } from "node:string_decoder";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";

// No check consumes another check's outputs. Running them together lets the
// PostgreSQL-backed pytest suite overlap with static and frontend checks.
const checks = [
  "check:ruff",
  "check:pyright",
  "check:pytest",
  "check:contracts",
  "check:typescript",
];
const children = new Set();
const root = fileURLToPath(new URL("..", import.meta.url));
const sourcePaths = ["apps", "packages"].flatMap((group) =>
  readdirSync(join(root, group), { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && existsSync(join(root, group, entry.name, "src")))
    .map((entry) => join(root, group, entry.name, "src")),
);
// The dev container may retain non-editable workspace wheels after an edit.
// Put the mounted source trees first so a green test never exercises old code.
const env = {
  ...process.env,
  PYTHONPATH: [...sourcePaths, process.env.PYTHONPATH].filter(Boolean).join(delimiter),
};

function forwardLines(stream, label, destination) {
  const decoder = new StringDecoder("utf8");
  let pending = "";
  stream.on("data", (chunk) => {
    pending += decoder.write(chunk);
    let end;
    while ((end = pending.indexOf("\n")) !== -1) {
      destination.write(`[${label}] ${pending.slice(0, end + 1)}`);
      pending = pending.slice(end + 1);
    }
  });
  stream.on("end", () => {
    pending += decoder.end();
    if (pending) destination.write(`[${label}] ${pending}\n`);
  });
}

function runCheck(name) {
  return new Promise((resolve) => {
    const started = performance.now();
    process.stdout.write(`[gate] starting ${name}\n`);
    const child = spawn("pnpm", ["run", name], {
      cwd: root,
      env,
      shell: process.platform === "win32",
      stdio: ["inherit", "pipe", "pipe"],
    });
    children.add(child);
    forwardLines(child.stdout, name, process.stdout);
    forwardLines(child.stderr, name, process.stderr);
    child.on("error", (error) => {
      process.stderr.write(`[gate] ${name} could not start: ${error.message}\n`);
    });
    child.on("close", (code, signal) => {
      children.delete(child);
      const seconds = ((performance.now() - started) / 1000).toFixed(1);
      const result = code === 0 ? "passed" : `failed (${signal ?? code})`;
      process.stdout.write(`[gate] ${name}: ${result} in ${seconds}s\n`);
      resolve(code === 0);
    });
  });
}

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    for (const child of children) child.kill(signal);
    process.exitCode = 1;
  });
}

const started = performance.now();
const results = await Promise.all(checks.map(runCheck));
const seconds = ((performance.now() - started) / 1000).toFixed(1);
process.stdout.write(`[gate] ${results.every(Boolean) ? "passed" : "failed"} in ${seconds}s\n`);
if (results.some((passed) => !passed)) process.exitCode = 1;
