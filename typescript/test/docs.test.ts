import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const LIB = "LombokAuth";
const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const read = (p: string): string => readFileSync(join(root, p), "utf8").replace(/\r\n/g, "\n");
const version = read("version.txt").trim();
const DOCS = ["changelog", "map", "structure_repo", "full_summary_project", "guide_how_to_use", "how_to_dist", "development_ide", "API", "Lang", "SPEC"];

test("doctor-lite: vector sha256 in SPEC equals the vector file", () => {
  const sha = createHash("sha256").update(readFileSync(join(root, "vectors", "lombokauth-vectors-v1.json"))).digest("hex");
  assert.ok(read(`docs/SPEC_${LIB}_v${version}.md`).includes(sha), "SPEC hash");
  assert.ok(read("vectors/README.md").includes(sha), "vectors/README hash");
});

test("doctor-lite: SPEC opens with the mandatory normative sentence", () => {
  assert.ok(read(`docs/SPEC_${LIB}_v${version}.md`).includes("This document is the normative cross-language contract. Every language port MUST produce byte-identical output for all specified inputs. Deviations from this specification are bugs."));
});

test("doctor-lite: versions agree and the 10 public standard documents exist", () => {
  assert.equal(JSON.parse(read("typescript/package.json")).version, version);
  assert.match(read("rust/Cargo.toml"), new RegExp(`^version = "${version.replace(/\./g, "\\.")}"`, "m"));
  for (const kind of DOCS) assert.ok(existsSync(join(root, "docs", `${kind}_${LIB}_v${version}.md`)), kind);
});

test("doctor-lite (ADR-024): internal documents are never tracked by git", () => {
  let tracked: string;
  try {
    tracked = execFileSync("git", ["ls-files", "docs", "map"], { cwd: root, encoding: "utf8" });
  } catch {
    return; // not a git checkout (for example an extracted archive): nothing to verify
  }
  assert.ok(!/architecture|masterplan/i.test(tracked), tracked);
  assert.ok(!/^map\//m.test(tracked));
});

test("doctor-lite: license files are real texts and match the SPDX expression", () => {
  assert.ok(readFileSync(join(root, "LICENSE-APACHE")).length >= 1000);
  assert.ok(readFileSync(join(root, "LICENSE-MIT")).length >= 1000);
  assert.equal(JSON.parse(read("typescript/package.json")).license, "Apache-2.0 OR MIT");
  assert.match(read("rust/Cargo.toml"), /license = "Apache-2\.0 OR MIT"/);
});

test("doctor-lite: public markdown has no emoji and no forbidden ownership phrases", () => {
  const files = ["README.md", "CHANGELOG.md", "SECURITY.md", "CONTRIBUTING.md", "vectors/README.md", "docs/TECH_DEBT.md"];
  for (const d of DOCS) files.push(`docs/${d}_${LIB}_v${version}.md`);
  const emoji = /[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{2B00}-\u{2BFF}\u{FE0F}]/u;
  const forbidden = /Part of \[?LombokRAG|Library\s*#\d+|Peran di RAG|Role in RAG|Purpose in RAG|bagian dari Lombok(RAG|Clarion|DocFlow|PDF|AgenticAuto|Miner|DNSProxy|Proxy)|khusus (untuk )?RAG/;
  for (const f of files) {
    const text = read(f);
    assert.ok(!emoji.test(text), `emoji in ${f}`);
    if (f !== `docs/map_${LIB}_v${version}.md`) {
      assert.ok(!forbidden.test(text), `forbidden phrase in ${f}`);
      assert.ok(!/Clarion/.test(text), `application name outside map_ in ${f} (ADR-019)`);
    }
  }
});

test("doctor-lite: .gitignore carries the three ADR-024 lines", () => {
  const g = read(".gitignore");
  for (const line of ["/map", "/docs/*architecture*.*", "/docs/*masterplan*.*"]) assert.ok(g.split("\n").includes(line), line);
});

test("doctor-lite: locale catalogs have identical keys", () => {
  const en = Object.keys(JSON.parse(read(`locales/en/${LIB.toLowerCase()}.json`))).sort();
  const id = Object.keys(JSON.parse(read(`locales/id/${LIB.toLowerCase()}.json`))).sort();
  assert.deepEqual(id, en);
  const lang = read(`docs/Lang_${LIB}_v${version}.md`);
  for (const k of en) assert.ok(lang.includes(k), `Lang_ lists ${k}`);
});

test("doctor-lite (style): every tracked text file is ASCII-only (no emoji, arrows, dashes or box drawing)", () => {
  let tracked: string[];
  try {
    tracked = execFileSync("git", ["ls-files"], { cwd: root, encoding: "utf8" }).split("\n").filter((f) => f !== "");
  } catch {
    return;
  }
  const text = /\.(md|ts|rs|mjs|js|json|yml|yaml|toml|txt)$|^\.git(ignore|attributes)$/;
  for (const f of tracked.filter((x) => text.test(x))) {
    const s = readFileSync(join(root, f), "utf8");
    const m = /[^\x00-\x7f]/.exec(s);
    assert.equal(m, null, `${f}: non-ASCII character U+${m ? m[0].codePointAt(0)!.toString(16).toUpperCase() : ""}`);
  }
});
