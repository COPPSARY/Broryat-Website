import { db, hasDatabaseUrl, tableExists } from "./db";

async function safeCount(tableName: string, column = "*") {
  if (!(await tableExists(tableName))) {
    return 0;
  }

  if (column !== "*" && !/^[a-z_][a-z0-9_]*$/i.test(column)) {
    return 0;
  }

  if (column === "*") {
    const rows = await db()<{ count: string }[]>`select count(*) as count from ${db().unsafe(tableName)}`;
    return Number(rows[0]?.count ?? 0);
  }

  const rows = await db()<{ count: string }[]>`select count(distinct ${db().unsafe(column)}) as count from ${db().unsafe(tableName)}`;
  return Number(rows[0]?.count ?? 0);
}

export async function getDashboardStats() {
  if (!hasDatabaseUrl()) {
    return {
      scans: 0,
      users: 0,
      urlReports: 0,
      userPreferences: 0,
      groups: 0,
      articles: 0,
      recentScans: [],
      groupsList: [],
    };
  }

  const scans = await safeCount("scan_records");
  const users = await safeCount("scan_records", "user_id");
  const urlReports = await safeCount("url_reports");
  const userPreferences = await safeCount("user_preferences");
  const groups = await safeCount("group_preferences");
  const articles = await safeCount("articles");

  const recentScans = (await tableExists("scan_records"))
    ? await db()<{
        id: string;
        created_at: Date;
        user_id: string;
        chat_type: string;
        input_type: string;
        final_risk_level: string;
        domain: string | null;
      }[]>`
        select id, created_at, user_id::text, chat_type, input_type, final_risk_level, domain
        from scan_records
        order by created_at desc
        limit 10
      `
    : [];

  const groupsList = (await tableExists("group_preferences"))
    ? await db()<{
        chat_id: string;
        group_name: string | null;
        language: string | null;
        updated_at: Date;
      }[]>`
        select chat_id::text, group_name, language, updated_at
        from group_preferences
        order by updated_at desc
        limit 10
      `
    : [];

  return { scans, users, urlReports, userPreferences, groups, articles, recentScans, groupsList };
}
