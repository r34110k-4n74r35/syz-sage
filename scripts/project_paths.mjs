import os from "node:os";
import path from "node:path";

export async function writablePath(value) {
  // Explicit destinations may be anywhere. Leave symlink traversal, including
  // dangling targets, to ordinary filesystem operations.
  const expanded = value === "~" ? os.homedir()
    : value.startsWith("~/") ? path.join(os.homedir(), value.slice(2)) : value;
  return path.resolve(expanded);
}
