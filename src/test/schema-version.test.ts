// @vitest-environment node
import { readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { CODE_SCHEMA_LEVEL } from "@/lib/schema-version";

describe("schema level reported by the health probe", () => {
  it("equals the highest migration number in db/", () => {
    const numbers = readdirSync(new URL("../../db", import.meta.url))
      .map((f) => /^(\d+)_.*\.sql$/.exec(f)?.[1])
      .filter((n): n is string => Boolean(n))
      .map(Number);
    expect(CODE_SCHEMA_LEVEL).toBe(String(Math.max(...numbers)).padStart(4, "0"));
  });
});
