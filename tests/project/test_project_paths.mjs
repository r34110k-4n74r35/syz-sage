import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { writablePath } from "../../scripts/project_paths.mjs";

const projectDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

test("explicit workbook destinations are unrestricted and normalized", async () => {
  const local = await fs.mkdtemp(path.join(projectDirectory, ".syz-sage-tmp-"));
  try {
    // Model a checkout and a separate user export directory without touching
    // any real user files outside this disposable fixture.
    const checkout = path.join(local, "checkout");
    const exports = path.join(local, "user-exports");
    await fs.mkdir(checkout);
    await fs.mkdir(exports);
    const requested = path.join(checkout, "..", "user-exports", "new", "report.xlsx");
    const normalized = await writablePath(requested);
    assert.equal(normalized, path.join(exports, "new", "report.xlsx"));
    await fs.mkdir(path.dirname(normalized));
    await fs.writeFile(normalized, "explicit export");
    assert.equal(await fs.readFile(normalized, "utf8"), "explicit export");

    // Normalizing an absolute path outside the actual project does not create it.
    const outside = path.join(projectDirectory, "..", "syz-sage-path-test", "report.xlsx");
    assert.equal(await writablePath(outside), outside);
    assert.equal(await writablePath("~"), path.resolve(os.homedir()));
    assert.equal(
      await writablePath("~/syz-sage-path-test/report.xlsx"),
      path.join(os.homedir(), "syz-sage-path-test", "report.xlsx"),
    );
  } finally {
    await fs.rm(local, { recursive: true, force: true });
  }
});

test("explicit symlinks and hardlinks follow ordinary filesystem semantics", async () => {
  const local = await fs.mkdtemp(path.join(projectDirectory, ".syz-sage-tmp-"));
  try {
    const exports = path.join(local, "user-exports");
    await fs.mkdir(exports);
    const link = path.join(local, "selected-export-directory");
    await fs.symlink(exports, link, "dir");
    await fs.writeFile(await writablePath(path.join(link, "report.xlsx")), "symlink export");
    assert.equal(await fs.readFile(path.join(exports, "report.xlsx"), "utf8"), "symlink export");

    const original = path.join(exports, "original");
    const hardlink = path.join(exports, "hardlink");
    await fs.writeFile(original, "before");
    await fs.link(original, hardlink);
    await fs.writeFile(await writablePath(hardlink), "after");
    assert.equal(await fs.readFile(original, "utf8"), "after");
  } finally {
    await fs.rm(local, { recursive: true, force: true });
  }
});

test("dangling symlink chains can create their targets and cycles retain filesystem errors", async () => {
  const local = await fs.mkdtemp(path.join(projectDirectory, ".syz-sage-tmp-"));
  try {
    for (const kind of ["relative", "absolute"]) {
      const destination = path.join(local, `${kind}-link`);
      const middle = path.join(local, `${kind}-middle`);
      const target = path.join(local, `${kind}-target`);
      await fs.symlink(kind === "relative" ? path.basename(middle) : middle, destination);
      await fs.symlink(kind === "relative" ? target : path.basename(target), middle);
      await fs.writeFile(await writablePath(destination), `${kind} export`);
      assert.equal(await fs.readFile(target, "utf8"), `${kind} export`);
    }

    const left = path.join(local, "cycle-left");
    const right = path.join(local, "cycle-right");
    await fs.symlink(path.basename(right), left);
    await fs.symlink(left, right);
    await assert.rejects(fs.writeFile(await writablePath(left), "blocked by filesystem"), { code: "ELOOP" });
  } finally {
    await fs.rm(local, { recursive: true, force: true });
  }
});
