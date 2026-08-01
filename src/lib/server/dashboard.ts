import { db, hasDatabaseUrl, tableExists } from "./db";

const emptyStats = {
  scans: 0,
  users: 0,
  urlReports: 0,
  userPreferences: 0,
  groups: 0,
  articles: 0,
  recentScans: [] as any[],
  groupsList: [] as any[],
};

export async function getDashboardStats() {
  if (!hasDatabaseUrl() || !(await tableExists("scan_records"))) {
    return emptyStats;
  }

  const rows = await db()<{
    counts: Record<string, string>;
    recent_scans: {
      id: string;
      created_at: string;
      user_id: string;
      chat_type: string;
      input_type: string;
      final_risk_level: string;
      domain: string | null;
    }[];
    groups_list: { chat_id: string; group_name: string | null; language: string | null; updated_at: string }[];
  }[]>`
    with counts as (
      select 'scans' as key, count(*) as value from scan_records
      union all
      select 'users', count(distinct user_id) from scan_records
      union all
      select 'url_reports', count(*) from url_reports
      union all
      select 'user_preferences', count(*) from user_preferences
      union all
      select 'groups', count(*) from group_preferences
      union all
      select 'articles', count(*) from articles
    ),
    recent as (
      select id, created_at, user_id::text, chat_type, input_type, final_risk_level, domain
      from scan_records order by created_at desc limit 10
    ),
    groups_list as (
      select chat_id::text, group_name, language, updated_at
      from group_preferences order by updated_at desc limit 10
    )
    select
      (select coalesce(jsonb_object_agg(key, value), '{}'::jsonb) from counts) as counts,
      (select coalesce(jsonb_agg(recent), '[]'::jsonb) from recent) as recent_scans,
      (select coalesce(jsonb_agg(groups_list), '[]'::jsonb) from groups_list) as groups_list
  `;

  const r = rows[0];
  const counts = r?.counts ?? {};

  return {
    scans: Number(counts.scans ?? 0),
    users: Number(counts.users ?? 0),
    urlReports: Number(counts.url_reports ?? 0),
    userPreferences: Number(counts.user_preferences ?? 0),
    groups: Number(counts.groups ?? 0),
    articles: Number(counts.articles ?? 0),
    recentScans: (r?.recent_scans ?? []).map((s) => ({ ...s, created_at: new Date(s.created_at) })),
    groupsList: (r?.groups_list ?? []).map((g) => ({ ...g, updated_at: new Date(g.updated_at) })),
  };
}
