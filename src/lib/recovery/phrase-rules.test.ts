import { describe, expect, it } from "vitest";
import { kitFileName } from "./vault-rules";

describe("recovery kit rules", () => {
  it("names the kit file by date only", () => {
    expect(kitFileName("codes", new Date("2026-11-11T10:00:00Z"), "pdf")).toBe("rout-herstelcodes-2026-11-11.pdf");
  });
});
