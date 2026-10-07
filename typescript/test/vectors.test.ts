import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import * as lib from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectorPath = join(here, "..", "..", "..", "vectors", "lombokauth-vectors-v1.json");
type Case = { name: string; fn: string; args: unknown[]; expect: { result?: unknown; error?: string } };
const doc = JSON.parse(readFileSync(vectorPath, "utf8")) as { groups: { name: string; cases: Case[] }[] };


let total = 0;
for (const group of doc.groups) {
  test(`vectors: ${group.name} (${group.cases.length} cases)`, () => {
    for (const k of group.cases) {
      total++;
      if (k.expect.error !== undefined) {
        assert.throws(() => lib.call(k.fn, k.args), (err: unknown) => err instanceof lib.LombokAuthError && err.code === k.expect.error, k.name);
      } else {
        assert.deepEqual(JSON.parse(JSON.stringify(lib.call(k.fn, k.args))), k.expect.result, k.name);
      }
    }
  });
}
test("vector count meets GP-11 (>= 100)", () => {
  assert.ok(total >= 100, `executed ${total}`);
});
