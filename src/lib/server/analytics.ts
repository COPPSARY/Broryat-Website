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
      const rows = await db()<{ input_type: string; count: string }[]>`
        select input_type, count(*) as count
        from scan_records
        where created_at >= ${from} and created_at <= ${to}
        group by 1
      `;
      const activeGroupsRows = await db()<{ count: string }[]>`
        select count(distinct chat_id) as count
        from scan_records
        where created_at >= ${from} and created_at <= ${to} and chat_type = 'group'
      `;

      const byType = (type: string) => Number(rows.find((r) => r.input_type === type)?.count ?? 0);
      return {
        messages: byType("text"),
        files: byType("file"),
        urls: byType("url"),
        forwarded: byType("forwarded"),
        activeGroups: Number(activeGroupsRows[0]?.count ?? 0),
        total: rows.reduce((sum, r) => sum + Number(r.count), 0),
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

    const newUsersRows = await db()<{ count: string }[]>`
      with first_seen as (
        select user_id, min(created_at) as first_at from scan_records group by user_id
      )
      select count(*) as count from first_seen where first_at >= ${from} and first_at <= ${to}
    `;

    const activityRows = await db()<{ user_id: string; active_days: string; scans: string }[]>`
      select user_id::text, count(distinct date_trunc('day', created_at)) as active_days, count(*) as scans
      from scan_records
      where created_at >= ${from} and created_at <= ${to}
      group by 1
    `;

    const returningUsers = activityRows.filter((r) => Number(r.active_days) > 1).length;
    const totalScansInRange = activityRows.reduce((sum, r) => sum + Number(r.scans), 0);
    const avgScansPerUser = activityRows.length > 0 ? totalScansInRange / activityRows.length : 0;

    async function retentionFor(windowMs: number) {
      const priorFrom = new Date(from.getTime() - windowMs);
      const priorTo = from;
      const [priorUsers, returned] = await Promise.all([
        db()<{ user_id: string }[]>`
          select distinct user_id::text from scan_records where created_at >= ${priorFrom} and created_at < ${priorTo}
        `,
        db()<{ user_id: string }[]>`
          select distinct user_id::text from scan_records
          where created_at >= ${from} and created_at <= ${to}
            and user_id in (
              select distinct user_id from scan_records where created_at >= ${priorFrom} and created_at < ${priorTo}
            )
        `,
      ]);
      return priorUsers.length > 0 ? (returned.length / priorUsers.length) * 100 : 0;
    }

    const [retention7d, retention30d] = await Promise.all([
      retentionFor(7 * 24 * 60 * 60 * 1000),
      retentionFor(30 * 24 * 60 * 60 * 1000),
    ]);

    const topUsers = await db()<{ user_id: string; username: string | null; first_name: string | null; scans: string; last_active: Date }[]>`
      select sr.user_id::text, up.username, up.first_name, count(*) as scans, max(sr.created_at) as last_active
      from scan_records sr
      left join user_preferences up on up.user_id = sr.user_id
      where sr.created_at >= ${from} and sr.created_at <= ${to}
      group by 1, 2, 3
      order by scans desc
      limit 10
    `;

    const topGroups = await db()<{ chat_id: string; group_name: string | null; scans: string; last_active: Date }[]>`
      select sr.chat_id::text, gp.group_name, count(*) as scans, max(sr.created_at) as last_active
      from scan_records sr
      left join group_preferences gp on gp.chat_id = sr.chat_id
      where sr.created_at >= ${from} and sr.created_at <= ${to} and sr.chat_type = 'group'
      group by 1, 2
      order by scans desc
      limit 10
    `;

    return {
      newUsers: Number(newUsersRows[0]?.count ?? 0),
      returningUsers,
      avgScansPerUser: Math.round(avgScansPerUser * 10) / 10,
      retention7d: Math.round(retention7d * 10) / 10,
      retention30d: Math.round(retention30d * 10) / 10,
      topUsers: topUsers.map((u) => ({
        userId: u.user_id,
        username: u.username ?? u.first_name,
        scans: Number(u.scans),
        lastActive: u.last_active,
      })),
      topGroups: topGroups.map((g) => ({
        chatId: g.chat_id,
        groupName: g.group_name,
        scans: Number(g.scans),
        lastActive: g.last_active,
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

    const topDomains = await db()<{ domain: string; count: string }[]>`
      select domain, count(*) as count
      from scan_records
      where created_at >= ${from} and created_at <= ${to}
        and final_risk_level in ('MEDIUM', 'HIGH') and domain is not null
      group by 1
      order by 2 desc
      limit 10
    `;

    const topHashes = await db()<{ sha256: string; file_name: string | null; count: string }[]>`
      select sha256, max(file_name) as file_name, count(*) as count
      from scan_records
      where created_at >= ${from} and created_at <= ${to}
        and input_type = 'file' and final_risk_level in ('MEDIUM', 'HIGH') and sha256 is not null
      group by 1
      order by 3 desc
      limit 10
    `;

    const now = to;
    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const twoWeeksAgo = new Date(now.getTime() - 14 * 24 * 60 * 60 * 1000);

    const trendRows = await db()<{ domain: string; this_week: string; last_week: string }[]>`
      select domain,
        count(*) filter (where created_at >= ${weekAgo}) as this_week,
        count(*) filter (where created_at >= ${twoWeeksAgo} and created_at < ${weekAgo}) as last_week
      from scan_records
      where created_at >= ${twoWeeksAgo} and created_at <= ${now}
        and final_risk_level in ('MEDIUM', 'HIGH') and domain is not null
      group by 1
      having count(*) filter (where created_at >= ${weekAgo}) > count(*) filter (where created_at >= ${twoWeeksAgo} and created_at < ${weekAgo})
      order by 2 desc
      limit 10
    `;

    const labelRows = await db()<{ vt_detection_names: string[] | null }[]>`
      select vt_detection_names
      from scan_records
      where created_at >= ${from} and created_at <= ${to}
        and final_risk_level in ('MEDIUM', 'HIGH') and vt_detection_names is not null
    `;

    const keywordCounts = new Map<string, number>();
    for (const row of labelRows) {
      const labels = Array.isArray(row.vt_detection_names) ? row.vt_detection_names : [];
      for (const label of labels) {
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
  const [totals, categories, hours, agreement] = await Promise.all([
    db()<{ total: string; safe: string }[]>`
      select count(*) as total, count(*) filter (where final_risk_level = 'SAFE') as safe
      from scan_records where created_at >= ${from} and created_at <= ${to}
    `,
    getThreatCategories(days),
    getActiveHours(days),
    db()<{ comparable: string; agree: string }[]>`
      select
        count(*) filter (where ai_risk_level is not null and final_risk_level is not null) as comparable,
        count(*) filter (where upper(ai_risk_level) = upper(final_risk_level)) as agree
      from scan_records where created_at >= ${from} and created_at <= ${to}
    `,
  ]);

  const total = Number(totals[0]?.total ?? 0);
  if (total === 0) {
    return `No submissions were analyzed in the last ${days} days.`;
  }

  const safe = Number(totals[0]?.safe ?? 0);
  const safePct = Math.round((safe / total) * 100);
  const topThreat = categories.labels[0] ?? "no significant threats";

  const peakHourIndex = hours.data.indexOf(Math.max(...hours.data));
  const peakHour = peakHourIndex >= 0 ? Number(hours.labels[peakHourIndex]?.slice(0, 2) ?? 0) : null;
  const peakPeriod = peakHour === null ? "throughout the day" : peakHour < 12 ? "in the morning" : peakHour < 18 ? "in the afternoon" : "in the evening";

  const comparable = Number(agreement[0]?.comparable ?? 0);
  const agree = Number(agreement[0]?.agree ?? 0);
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
