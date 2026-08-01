import { db, hasDatabaseUrl, tableExists } from "./db";

export type GroupFilters = {
  from?: Date;
  to?: Date;
  riskLevel?: string;
  language?: string;
  groupSearch?: string;
};

export type GroupStat = {
  chatId: string;
  groupName: string | null;
  language: string | null;
  updatedAt: Date;
  messagesAnalyzed: number;
  maliciousDetected: number;
  threatRate: number;
  lastActivity: Date | null;
  activeMembers: number;
  status: "Active" | "Idle";
};

export async function getGroupProtectionStats(filters: GroupFilters = {}): Promise<GroupStat[]> {
  if (!hasDatabaseUrl() || !(await tableExists("group_preferences"))) {
    return [];
  }

  const from = filters.from ?? null;
  const to = filters.to ?? null;
  const riskLevel = filters.riskLevel ?? null;
  const language = filters.language ?? null;
  const groupSearch = filters.groupSearch ? `%${filters.groupSearch}%` : null;

  const rows = await db()<{
    chat_id: string;
    group_name: string | null;
    language: string | null;
    updated_at: Date;
    messages_analyzed: string;
    malicious_detected: string;
    active_members: string;
    last_activity: Date | null;
  }[]>`
    select
      gp.chat_id::text,
      gp.group_name,
      gp.language,
      gp.updated_at,
      count(sr.id) filter (
        where (${from}::timestamp is null or sr.created_at >= ${from})
          and (${to}::timestamp is null or sr.created_at <= ${to})
          and (${riskLevel}::text is null or sr.final_risk_level = ${riskLevel})
      ) as messages_analyzed,
      count(sr.id) filter (
        where sr.final_risk_level in ('MEDIUM', 'HIGH')
          and (${from}::timestamp is null or sr.created_at >= ${from})
          and (${to}::timestamp is null or sr.created_at <= ${to})
          and (${riskLevel}::text is null or sr.final_risk_level = ${riskLevel})
      ) as malicious_detected,
      count(distinct sr.user_id) filter (
        where (${from}::timestamp is null or sr.created_at >= ${from})
          and (${to}::timestamp is null or sr.created_at <= ${to})
      ) as active_members,
      max(sr.created_at) as last_activity
    from group_preferences gp
    left join scan_records sr on sr.chat_id = gp.chat_id and sr.chat_type = 'group'
    where (${language}::text is null or gp.language = ${language})
      and (${groupSearch}::text is null or gp.group_name ilike ${groupSearch} or gp.chat_id::text ilike ${groupSearch})
    group by gp.chat_id, gp.group_name, gp.language, gp.updated_at
    order by messages_analyzed desc
  `;

  const idleThreshold = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

  return rows.map((r) => {
    const messagesAnalyzed = Number(r.messages_analyzed);
    const maliciousDetected = Number(r.malicious_detected);
    return {
      chatId: r.chat_id,
      groupName: r.group_name,
      language: r.language,
      updatedAt: r.updated_at,
      messagesAnalyzed,
      maliciousDetected,
      threatRate: messagesAnalyzed > 0 ? Math.round((maliciousDetected / messagesAnalyzed) * 1000) / 10 : 0,
      lastActivity: r.last_activity,
      activeMembers: Number(r.active_members),
      status: r.last_activity && r.last_activity >= idleThreshold ? "Active" : "Idle",
    };
  });
}

export async function getDistinctGroupLanguages(): Promise<string[]> {
  if (!hasDatabaseUrl() || !(await tableExists("group_preferences"))) {
    return [];
  }
  const rows = await db()<{ language: string | null }[]>`
    select distinct language from group_preferences where language is not null order by 1
  `;
  return rows.map((r) => r.language).filter((l): l is string => Boolean(l));
}
