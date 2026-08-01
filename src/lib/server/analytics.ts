import { db, hasDatabaseUrl, tableExists } from "./db";

export type DateRange = { from?: Date; to?: Date };

const RISK_BUCKETS = { SAFE: "Safe", LOW: "Suspicious", MEDIUM: "Suspicious", HIGH: "High risk" } as const;

const THREAT_CATEGORY_KEYWORDS: Record<string, string[]> = {
  Phishing: ["phish"],
  Malware: ["troj", "malware", "virus", "worm", "ransom", "spyware", "backdoor", "rootkit", "exploit"],
  Scam: ["scam"],
  Impersonation: ["impersonat", "fake", "spoof"],
  Spam: ["spam"],
  Fraud: ["fraud"],
};

function classifyDetectionLabel(label: string): string {
  const lower = label.toLowerCase();
  for (const [category, keywords] of Object.entries(THREAT_CATEGORY_KEYWORDS)) {
    if (keywords.some((keyword) => lower.includes(keyword))) {
      return category;
    }
  }
  return "Unknown";
}

function emptyChart() {
  return { labels: [] as string[], datasets: [] as { label: string; data: number[] }[] };
}

async function guarded<T>(table: string, fallback: T, fn: () => Promise<T>): Promise<T> {
  if (!hasDatabaseUrl() || !(await tableExists(table))) {
    return fallback;
  }
  return fn();
}

function windowBounds(days: number, range?: DateRange) {
  const to = range?.to ?? new Date();
  const from = range?.from ?? new Date(to.getTime() - days * 24 * 60 * 60 * 1000);
  return { from, to };
}

export async function getDailyScanVolume(days = 14, range?: DateRange) {
  return guarded("scan_records", emptyChart(), async () => {
    const { from, to } = windowBounds(days, range);
    const rows = await db()<{ day: string; input_type: string; count: string }[]>`
      select to_char(date_trunc('day', created_at), 'YYYY-MM-DD') as day, input_type, count(*) as count
      from scan_records
      where created_at >= ${from} and created_at <= ${to}
      group by 1, 2
      order by 1
    `;

    const labels = [...new Set(rows.map((r) => r.day))].sort();
    const types = [...new Set(rows.map((r) => r.input_type))];
    const datasets = types.map((type) => ({
      label: type,
      data: labels.map((day) => Number(rows.find((r) => r.day === day && r.input_type === type)?.count ?? 0)),
    }));

    return { labels, datasets };
  });
}

export async function getThreatTrend(days = 14, range?: DateRange) {
  return guarded("scan_records", emptyChart(), async () => {
    const { from, to } = windowBounds(days, range);
    const rows = await db()<{ day: string; final_risk_level: string; count: string }[]>`
      select to_char(date_trunc('day', created_at), 'YYYY-MM-DD') as day, final_risk_level, count(*) as count
      from scan_records
      where created_at >= ${from} and created_at <= ${to} and final_risk_level is not null
      group by 1, 2
      order by 1
    `;

    const labels = [...new Set(rows.map((r) => r.day))].sort();
    const buckets = ["Safe", "Suspicious", "High risk"];
    const datasets = buckets.map((bucket) => ({
      label: bucket,
      data: labels.map((day) =>
        rows
          .filter((r) => r.day === day && RISK_BUCKETS[r.final_risk_level as keyof typeof RISK_BUCKETS] === bucket)
          .reduce((sum, r) => sum + Number(r.count), 0),
      ),
    }));

    return { labels, datasets };
  });
}

export async function getThreatCategories(days = 30, range?: DateRange) {
  return guarded("scan_records", { labels: [] as string[], data: [] as number[] }, async () => {
    const { from, to } = windowBounds(days, range);
    const rows = await db()<{ vt_detection_names: string[] | null }[]>`
      select vt_detection_names
      from scan_records
      where created_at >= ${from} and created_at <= ${to}
        and final_risk_level in ('MEDIUM', 'HIGH')
        and vt_detection_names is not null
    `;

    const counts = new Map<string, number>();
    for (const row of rows) {
      const labels = Array.isArray(row.vt_detection_names) ? row.vt_detection_names : [];
      const categories = new Set(labels.map(classifyDetectionLabel));
      const applied = categories.size > 0 ? categories : new Set(["Unknown"]);
      for (const category of applied) {
        counts.set(category, (counts.get(category) ?? 0) + 1);
      }
    }

    const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
    return { labels: sorted.map(([label]) => label), data: sorted.map(([, count]) => count) };
  });
}

export async function getTelegramUsage(days = 7, range?: DateRange) {
  return guarded(
    "scan_records",
    { messages: 0, files: 0, urls: 0, forwarded: 0, activeGroups: 0, total: 0 },
    async () => {
      const { from, to } = windowBounds(days, range);
      const rows = await db()<{
        messages: string;
        files: string;
        urls: string;
        forwarded: string;
        active_groups: string;
        total: string;
      }[]>`
        select
          count(*) filter (where input_type = 'text') as messages,
          count(*) filter (where input_type = 'file') as files,
          count(*) filter (where input_type = 'url') as urls,
          count(*) filter (where input_type = 'forwarded') as forwarded,
          count(distinct chat_id) filter (where chat_type = 'group') as active_groups,
          count(*) as total
        from scan_records
        where created_at >= ${from} and created_at <= ${to}
      `;

      const r = rows[0];
      return {
        messages: Number(r?.messages ?? 0),
        files: Number(r?.files ?? 0),
        urls: Number(r?.urls ?? 0),
        forwarded: Number(r?.forwarded ?? 0),
        activeGroups: Number(r?.active_groups ?? 0),
        total: Number(r?.total ?? 0),
      };
    },
  );
}

export async function getLanguageDistribution(days = 30, range?: DateRange) {
  return guarded("scan_records", { labels: [] as string[], data: [] as number[] }, async () => {
    const { from, to } = windowBounds(days, range);
    const rows = await db()<{ language: string | null; count: string }[]>`
      select language, count(*) as count
      from scan_records
      where created_at >= ${from} and created_at <= ${to} and language is not null
      group by 1
      order by 2 desc
    `;
    return { labels: rows.map((r) => r.language ?? "unknown"), data: rows.map((r) => Number(r.count)) };
  });
}

export async function getActiveHours(days = 30, range?: DateRange) {
  return guarded("scan_records", { labels: [] as string[], data: [] as number[] }, async () => {
    const { from, to } = windowBounds(days, range);
    const rows = await db()<{ hour: number; count: string }[]>`
      select extract(hour from created_at)::int as hour, count(*) as count
      from scan_records
      where created_at >= ${from} and created_at <= ${to}
      group by 1
      order by 1
    `;
    const labels = Array.from({ length: 24 }, (_, h) => `${String(h).padStart(2, "0")}:00`);
    const data = Array.from({ length: 24 }, (_, h) => Number(rows.find((r) => r.hour === h)?.count ?? 0));
    return { labels, data };
  });
}

export async function getUserBehavior(days = 30, range?: DateRange) {
  const fallback = {
    newUsers: 0,
    returningUsers: 0,
    avgScansPerUser: 0,
    retention7d: 0,
    retention30d: 0,
    topUsers: [] as { userId: string; username: string | null; scans: number; lastActive: Date }[],
    topGroups: [] as { chatId: string; groupName: string | null; scans: number; lastActive: Date }[],
  };

  return guarded("scan_records", fallback, async () => {
    const { from, to } = windowBounds(days, range);
    const priorFrom7 = new Date(from.getTime() - 7 * 24 * 60 * 60 * 1000);
    const priorFrom30 = new Date(from.getTime() - 30 * 24 * 60 * 60 * 1000);

    const rows = await db()<{
      new_users: string;
      activity: { active_days: string; scans: string }[];
      top_users: { user_id: string; username: string | null; first_name: string | null; scans: string; last_active: string }[];
      top_groups: { chat_id: string; group_name: string | null; scans: string; last_active: string }[];
      prior7_count: string;
      returned7_count: string;
      prior30_count: string;
      returned30_count: string;
    }[]>`
      with window_scans as (
        select * from scan_records where created_at >= ${from} and created_at <= ${to}
      ),
      first_seen as (
        select user_id, min(created_at) as first_at from scan_records group by user_id
      ),
      activity as (
        select user_id, count(distinct date_trunc('day', created_at)) as active_days, count(*) as scans
        from window_scans group by user_id
      ),
      top_users as (
        select ws.user_id::text as user_id, up.username, up.first_name, count(*) as scans, max(ws.created_at) as last_active
        from window_scans ws
        left join user_preferences up on up.user_id = ws.user_id
        group by 1, 2, 3
        order by scans desc
        limit 10
      ),
      top_groups as (
        select ws.chat_id::text as chat_id, gp.group_name, count(*) as scans, max(ws.created_at) as last_active
        from window_scans ws
        left join group_preferences gp on gp.chat_id = ws.chat_id
        where ws.chat_type = 'group'
        group by 1, 2
        order by scans desc
        limit 10
      ),
      prior7 as (select distinct user_id from scan_records where created_at >= ${priorFrom7} and created_at < ${from}),
      returned7 as (
        select distinct user_id from window_scans where user_id in (select user_id from prior7)
      ),
      prior30 as (select distinct user_id from scan_records where created_at >= ${priorFrom30} and created_at < ${from}),
      returned30 as (
        select distinct user_id from window_scans where user_id in (select user_id from prior30)
      )
      select
        (select count(*) from first_seen where first_at >= ${from} and first_at <= ${to}) as new_users,
        (select coalesce(jsonb_agg(jsonb_build_object('active_days', active_days, 'scans', scans)), '[]'::jsonb) from activity) as activity,
        (select coalesce(jsonb_agg(top_users), '[]'::jsonb) from top_users) as top_users,
        (select coalesce(jsonb_agg(top_groups), '[]'::jsonb) from top_groups) as top_groups,
        (select count(*) from prior7) as prior7_count,
        (select count(*) from returned7) as returned7_count,
        (select count(*) from prior30) as prior30_count,
        (select count(*) from returned30) as returned30_count
    `;

    const r = rows[0];
    const activity = r?.activity ?? [];
    const topUsers = r?.top_users ?? [];
    const topGroups = r?.top_groups ?? [];

    const returningUsers = activity.filter((a) => Number(a.active_days) > 1).length;
    const totalScansInRange = activity.reduce((sum, a) => sum + Number(a.scans), 0);
    const avgScansPerUser = activity.length > 0 ? totalScansInRange / activity.length : 0;

    const prior7Count = Number(r?.prior7_count ?? 0);
    const prior30Count = Number(r?.prior30_count ?? 0);
    const retention7d = prior7Count > 0 ? (Number(r?.returned7_count ?? 0) / prior7Count) * 100 : 0;
    const retention30d = prior30Count > 0 ? (Number(r?.returned30_count ?? 0) / prior30Count) * 100 : 0;

    return {
      newUsers: Number(r?.new_users ?? 0),
      returningUsers,
      avgScansPerUser: Math.round(avgScansPerUser * 10) / 10,
      retention7d: Math.round(retention7d * 10) / 10,
      retention30d: Math.round(retention30d * 10) / 10,
      topUsers: topUsers.map((u) => ({
        userId: u.user_id,
        username: u.username ?? u.first_name,
        scans: Number(u.scans),
        lastActive: new Date(u.last_active),
      })),
      topGroups: topGroups.map((g) => ({
        chatId: g.chat_id,
        groupName: g.group_name,
        scans: Number(g.scans),
        lastActive: new Date(g.last_active),
      })),
    };
  });
}

export async function getSecurityInsights(days = 30, range?: DateRange) {
  const fallback = {
    topDomains: [] as { domain: string; count: number }[],
    topHashes: [] as { sha256: string; fileName: string | null; count: number }[],
    trending: [] as { domain: string; thisWeek: number; lastWeek: number }[],
    derivedKeywords: [] as { keyword: string; count: number }[],
  };

  return guarded("scan_records", fallback, async () => {
    const { from, to } = windowBounds(days, range);

    const now = to;
    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const twoWeeksAgo = new Date(now.getTime() - 14 * 24 * 60 * 60 * 1000);

    const rows = await db()<{
      domains: { domain: string; count: string }[];
      hashes: { sha256: string; file_name: string | null; count: string }[];
      trend: { domain: string; this_week: string; last_week: string }[];
      labels: (string[] | null)[];
    }[]>`
      with base as (
        select * from scan_records where created_at >= ${from} and created_at <= ${to}
      ),
      domains as (
        select domain, count(*) as count from base
        where final_risk_level in ('MEDIUM', 'HIGH') and domain is not null
        group by 1
        order by 2 desc
        limit 10
      ),
      hashes as (
        select sha256, max(file_name) as file_name, count(*) as count from base
        where input_type = 'file' and final_risk_level in ('MEDIUM', 'HIGH') and sha256 is not null
        group by 1
        order by 3 desc
        limit 10
      ),
      trend as (
        select domain,
          count(*) filter (where created_at >= ${weekAgo}) as this_week,
          count(*) filter (where created_at >= ${twoWeeksAgo} and created_at < ${weekAgo}) as last_week
        from base
        where created_at >= ${twoWeeksAgo}
          and final_risk_level in ('MEDIUM', 'HIGH') and domain is not null
        group by 1
        having count(*) filter (where created_at >= ${weekAgo}) > count(*) filter (where created_at >= ${twoWeeksAgo} and created_at < ${weekAgo})
        order by 2 desc
        limit 10
      ),
      labels as (
        select vt_detection_names from base
        where final_risk_level in ('MEDIUM', 'HIGH') and vt_detection_names is not null
      )
      select
        (select coalesce(jsonb_agg(domains), '[]'::jsonb) from domains) as domains,
        (select coalesce(jsonb_agg(hashes), '[]'::jsonb) from hashes) as hashes,
        (select coalesce(jsonb_agg(trend), '[]'::jsonb) from trend) as trend,
        (select coalesce(jsonb_agg(vt_detection_names), '[]'::jsonb) from labels) as labels
    `;

    const r = rows[0];
    const topDomains = r?.domains ?? [];
    const topHashes = r?.hashes ?? [];
    const trendRows = r?.trend ?? [];
    const labelRows = r?.labels ?? [];

    const keywordCounts = new Map<string, number>();
    for (const labels of labelRows) {
      for (const label of Array.isArray(labels) ? labels : []) {
        const tokens = label.toLowerCase().match(/[a-z]{4,}/g) ?? [];
        for (const token of new Set(tokens)) {
          if (["with", "generic", "score", "many"].includes(token)) continue;
          keywordCounts.set(token, (keywordCounts.get(token) ?? 0) + 1);
        }
      }
    }
    const derivedKeywords = [...keywordCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 15)
      .map(([keyword, count]) => ({ keyword, count }));

    return {
      topDomains: topDomains.map((r) => ({ domain: r.domain, count: Number(r.count) })),
      topHashes: topHashes.map((r) => ({ sha256: r.sha256, fileName: r.file_name, count: Number(r.count) })),
      trending: trendRows.map((r) => ({ domain: r.domain, thisWeek: Number(r.this_week), lastWeek: Number(r.last_week) })),
      derivedKeywords,
    };
  });
}

export async function getAiInsightsSummary(days = 7) {
  if (!hasDatabaseUrl() || !(await tableExists("scan_records"))) {
    return "Not enough data yet to generate insights.";
  }

  const { from, to } = windowBounds(days);
  const rows = await db()<{
    total: string;
    safe: string;
    comparable: string;
    agree: string;
    hours: { hour: number; count: string }[];
    labels: (string[] | null)[];
  }[]>`
    with base as (
      select * from scan_records where created_at >= ${from} and created_at <= ${to}
    ),
    hours as (
      select extract(hour from created_at)::int as hour, count(*) as count from base group by 1
    ),
    labels as (
      select vt_detection_names from base
      where final_risk_level in ('MEDIUM', 'HIGH') and vt_detection_names is not null
    )
    select
      count(*) as total,
      count(*) filter (where final_risk_level = 'SAFE') as safe,
      count(*) filter (where ai_risk_level is not null and final_risk_level is not null) as comparable,
      count(*) filter (where upper(ai_risk_level) = upper(final_risk_level)) as agree,
      (select coalesce(jsonb_agg(hours), '[]'::jsonb) from hours) as hours,
      (select coalesce(jsonb_agg(vt_detection_names), '[]'::jsonb) from labels) as labels
    from base
  `;

  const r = rows[0];
  const total = Number(r?.total ?? 0);
  if (total === 0) {
    return `No submissions were analyzed in the last ${days} days.`;
  }

  const safe = Number(r?.safe ?? 0);
  const safePct = Math.round((safe / total) * 100);

  const categoryCounts = new Map<string, number>();
  for (const labels of r?.labels ?? []) {
    const categories = new Set((Array.isArray(labels) ? labels : []).map(classifyDetectionLabel));
    const applied = categories.size > 0 ? categories : new Set(["Unknown"]);
    for (const category of applied) {
      categoryCounts.set(category, (categoryCounts.get(category) ?? 0) + 1);
    }
  }
  const topThreat = [...categoryCounts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "no significant threats";

  const hourCounts = new Map((r?.hours ?? []).map((h) => [h.hour, Number(h.count)]));
  let peakHour: number | null = null;
  let peakCount = -1;
  for (const [hour, count] of hourCounts) {
    if (count > peakCount) {
      peakCount = count;
      peakHour = hour;
    }
  }
  const peakPeriod = peakHour === null ? "throughout the day" : peakHour < 12 ? "in the morning" : peakHour < 18 ? "in the afternoon" : "in the evening";

  const comparable = Number(r?.comparable ?? 0);
  const agree = Number(r?.agree ?? 0);
  const agreementPct = comparable > 0 ? Math.round((agree / comparable) * 100) : null;

  const parts = [
    `During the last ${days} days, Broryat analyzed ${total.toLocaleString()} submissions.`,
    `${safePct}% were safe, while ${topThreat.toLowerCase()} remained the most common threat.`,
    `Activity peaked ${peakPeriod}.`,
  ];
  if (agreementPct !== null) {
    parts.push(`AI and VirusTotal verdicts agreed on ${agreementPct}% of comparable scans.`);
  }

  return parts.join(" ");
}
