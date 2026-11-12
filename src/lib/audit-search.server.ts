/**
 * Single read path for the admin audit log (db/0227 rout_audit_search).
 * Every filter is bound as a value and LIKE wildcards are escaped in the
 * database, so no search term can change which rows the query considers.
 * The database itself refuses callers that are not admins.
 */
import { sql } from "@/lib/neon";

export type AuditSearchRow = {
  id: string;
  adminEmail: string | null;
  action: string;
  targetUserId: string | null;
  targetLabel: string | null;
  notes: string | null;
  createdAt: string;
};

export async function searchAuditLog(opts: {
  adminEmail?: string | null;
  action?: string | null;
  actions?: readonly string[] | null;
  search?: string | null;
  from?: string | null;
  to?: string | null;
  cursorAt?: string | null;
  cursorId?: string | null;
  offset?: number;
  limit: number;
}): Promise<AuditSearchRow[] & { total?: number }> {
  const rows = (await sql`
    select id, admin_email, action, target_user_id, target_label, notes,
           to_json(created_at) as created_at, total
      from public.rout_audit_search(
        ${opts.adminEmail?.trim() || null}, ${opts.action || null}, ${opts.actions ? [...opts.actions] : null}::text[],
        ${opts.search?.trim().slice(0, 200) || null},
        ${opts.from ?? null}::timestamptz, ${opts.to ?? null}::timestamptz,
        ${opts.cursorAt ?? null}::timestamptz, ${opts.cursorId ?? null}::uuid,
        ${opts.offset ?? 0}::int, ${opts.limit}::int)
  `) as Record<string, unknown>[];
  const out = rows.map((r) => ({
    id: String(r["id"]),
    adminEmail: (r["admin_email"] as string | null) ?? null,
    action: String(r["action"]),
    targetUserId: (r["target_user_id"] as string | null) ?? null,
    targetLabel: (r["target_label"] as string | null) ?? null,
    notes: (r["notes"] as string | null) ?? null,
    createdAt: String(r["created_at"]),
  })) as AuditSearchRow[] & { total?: number };
  out.total = rows[0] ? Number(rows[0]["total"]) : 0;
  return out;
}

export async function auditActions(): Promise<string[]> {
  const rows = (await sql`select public.rout_audit_actions() as a`) as Record<string, unknown>[];
  return ((rows[0]?.["a"] as string[] | null) ?? []).slice().sort();
}
