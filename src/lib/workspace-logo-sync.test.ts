// @vitest-environment node
/**
 * Publishing the Workspace Studio makes the Studio photo the workspace logo.
 * The SQL in publishWorkspaceDraft applies WORKSPACE_LOGO_PATTERNS; this test
 * checks the TypeScript rule and that Postgres reads the patterns the same way.
 */
import { PGlite } from "@electric-sql/pglite";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { WORKSPACE_LOGO_PATTERNS, isWorkspaceLogoUrl, workspaceLogoAfterPublish } from "./workspace-studio";

const UPLOAD = "/api/public/avatar?path=0b8f2c1e-4d6a-4e6b-9a51-3f2a1c7d9e10%2Fphoto.webp";
const OLD = "https://cdn.example.com/old.png";

describe("workspace logo after a Studio publish", () => {
  it("a new uploaded photo becomes the logo", () => {
    expect(workspaceLogoAfterPublish(UPLOAD, OLD)).toBe(UPLOAD);
  });
  it("an https photo becomes the logo", () => {
    expect(workspaceLogoAfterPublish("https://img.example.com/me.jpg", OLD)).toBe("https://img.example.com/me.jpg");
  });
  it("removing the photo clears the logo", () => {
    expect(workspaceLogoAfterPublish("", OLD)).toBeNull();
    expect(workspaceLogoAfterPublish(null, OLD)).toBeNull();
  });
  it("an unsafe value keeps the current logo", () => {
    expect(workspaceLogoAfterPublish("javascript:alert(1)", OLD)).toBe(OLD);
    expect(workspaceLogoAfterPublish("http://insecure.example.com/a.png", OLD)).toBe(OLD);
    expect(workspaceLogoAfterPublish(`https://x.example.com/${"a".repeat(600)}`, OLD)).toBe(OLD);
  });
});

describe("Postgres applies the same logo patterns", () => {
  let db: PGlite;
  beforeAll(async () => {
    db = new PGlite();
  });
  afterAll(async () => {
    await db.close();
  });
  it.each([UPLOAD, "https://img.example.com/me.jpg", "javascript:alert(1)", "https://a b", "/api/public/avatar?path=../x"])(
    "%s",
    async (url) => {
      const r = await db.query<{ ok: boolean }>("select ($1 ~ $2 or $1 ~ $3) as ok", [url, ...WORKSPACE_LOGO_PATTERNS]);
      expect(r.rows[0]!.ok).toBe(isWorkspaceLogoUrl(url));
    },
  );
});
