/**
 * Cursor (keyset) pagination for the admin audit log.
 *
 * Offset pagination re-scans every skipped row and can skip or duplicate
 * entries when new audit rows land mid-browse. Keyset pagination anchors on
 * (created_at, id) so each page is O(page size) and always consistent.
 */
import { assertServiceRole } from "./deployment-status.server";

export type AuditCursorRow = {
  id: string;
  adminEmail: string | null;
  action: string;
  targetUserId: string | null;
  targetLabel: string | null;
  notes: string | null;
  createdAt: string;
};

export type AuditCursorFilters = {
  adminEmail?: string;
  action?: string;
  from?: string;
  to?: string;
  search?: string;
};

export function encodeCursor(row: { createdAt: string; id: string }): string {
  return Buffer.from(`${row.createdAt}|${row.id}`, "utf8").toString("base64url");
}

export function decodeCursor(cursor: string): { createdAt: string; id: string } | null {
  try {
    const [createdAt, id] = Buffer.from(cursor, "base64url").toString("utf8").split("|");
    if (!createdAt || !id) return null;
    return { createdAt, id };
  } catch {
    return null;
  }
}

export async function fetchAuditCursorPage(opts: {
  filters?: AuditCursorFilters;
  cursor?: string | null;
  perPage?: number;
}): Promise<{
  rows: AuditCursorRow[];
  nextCursor: string | null;
  hasMore: boolean;
  perPage: number;
}> {
  assertServiceRole();
  const filters = opts.filters ?? {};
  const perPage = Math.min(100, Math.max(10, opts.perPage ?? 20));
  let to: string | null = null;
  if (filters.to) { const d = new Date(filters.to); d.setHours(23, 59, 59, 999); to = d.toISOString(); }
  const anchor = opts.cursor ? decodeCursor(opts.cursor) : null;
  const { searchAuditLog } = await import("./audit-search.server");
  const data = await searchAuditLog({
    adminEmail: filters.adminEmail, action: filters.action, search: filters.search,
    from: filters.from ? new Date(filters.from).toISOString() : null, to,
    cursorAt: anchor?.createdAt ?? null, cursorId: anchor?.id ?? null, limit: perPage + 1,
  });

  const all = data ?? [];
  const hasMore = all.length > perPage;
  const page = hasMore ? all.slice(0, perPage) : all;

  const rows: AuditCursorRow[] = page;

  const last = rows[rows.length - 1];
  return {
    rows,
    nextCursor: hasMore && last ? encodeCursor(last) : null,
    hasMore,
    perPage,
  };
}
