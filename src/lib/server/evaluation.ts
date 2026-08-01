import { db, hasDatabaseUrl, tableExists } from "./db";

export type Kpi = { value: number; deltaPct: number | null };

export type EvaluationMetrics = {
  totalRequests: Kpi;
  vtCoverageRate: Kpi;
  vtPendingRate: Kpi;
  aiVtAgreementRate: Kpi;
  highRiskRate: Kpi;
};

function pct(numerator: number, denominator: number): number {
  return denominator > 0 ? Math.round((numerator / denominator) * 1000) / 10 : 0;
}

function delta(current: number, previous: number): number | null {
  if (previous === 0) return current === 0 ? 0 : null;
  return Math.round(((current - previous) / previous) * 1000) / 10;
}

export async function getEvaluationMetrics(): Promise<EvaluationMetrics> {
  const empty: EvaluationMetrics = {
    totalRequests: { value: 0, deltaPct: null },
    vtCoverageRate: { value: 0, deltaPct: null },
    vtPendingRate: { value: 0, deltaPct: null },
    aiVtAgreementRate: { value: 0, deltaPct: null },
    highRiskRate: { value: 0, deltaPct: null },
  };

  if (!hasDatabaseUrl() || !(await tableExists("scan_records"))) {
    return empty;
  }

  const now = new Date();
  const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const twoWeeksAgo = new Date(now.getTime() - 14 * 24 * 60 * 60 * 1000);

  const rows = await db()<{
    current_total: string;
    previous_total: string;
    current_vt_covered: string;
    previous_vt_covered: string;
    current_vt_pending: string;
    previous_vt_pending: string;
    current_comparable: string;
    current_agree: string;
    previous_comparable: string;
    previous_agree: string;
    current_high: string;
    previous_high: string;
  }[]>`
    select
      count(*) filter (where created_at >= ${weekAgo}) as current_total,
      count(*) filter (where created_at >= ${twoWeeksAgo} and created_at < ${weekAgo}) as previous_total,
      count(*) filter (where created_at >= ${weekAgo} and vt_status is not null) as current_vt_covered,
      count(*) filter (where created_at >= ${twoWeeksAgo} and created_at < ${weekAgo} and vt_status is not null) as previous_vt_covered,
      count(*) filter (where created_at >= ${weekAgo} and vt_status = 'pending') as current_vt_pending,
      count(*) filter (where created_at >= ${twoWeeksAgo} and created_at < ${weekAgo} and vt_status = 'pending') as previous_vt_pending,
      count(*) filter (where created_at >= ${weekAgo} and ai_risk_level is not null and final_risk_level is not null) as current_comparable,
      count(*) filter (where created_at >= ${weekAgo} and upper(ai_risk_level) = upper(final_risk_level)) as current_agree,
      count(*) filter (where created_at >= ${twoWeeksAgo} and created_at < ${weekAgo} and ai_risk_level is not null and final_risk_level is not null) as previous_comparable,
      count(*) filter (where created_at >= ${twoWeeksAgo} and created_at < ${weekAgo} and upper(ai_risk_level) = upper(final_risk_level)) as previous_agree,
      count(*) filter (where created_at >= ${weekAgo} and final_risk_level = 'HIGH') as current_high,
      count(*) filter (where created_at >= ${twoWeeksAgo} and created_at < ${weekAgo} and final_risk_level = 'HIGH') as previous_high
    from scan_records
  `;

  const r = rows[0];
  if (!r) return empty;

  const currentTotal = Number(r.current_total);
  const previousTotal = Number(r.previous_total);
  const currentVtCoverage = pct(Number(r.current_vt_covered), currentTotal);
  const previousVtCoverage = pct(Number(r.previous_vt_covered), previousTotal);
  const currentVtPending = pct(Number(r.current_vt_pending), currentTotal);
  const previousVtPending = pct(Number(r.previous_vt_pending), previousTotal);
  const currentAgreement = pct(Number(r.current_agree), Number(r.current_comparable));
  const previousAgreement = pct(Number(r.previous_agree), Number(r.previous_comparable));
  const currentHigh = pct(Number(r.current_high), currentTotal);
  const previousHigh = pct(Number(r.previous_high), previousTotal);

  return {
    totalRequests: { value: currentTotal, deltaPct: delta(currentTotal, previousTotal) },
    vtCoverageRate: { value: currentVtCoverage, deltaPct: delta(currentVtCoverage, previousVtCoverage) },
    vtPendingRate: { value: currentVtPending, deltaPct: delta(currentVtPending, previousVtPending) },
    aiVtAgreementRate: { value: currentAgreement, deltaPct: delta(currentAgreement, previousAgreement) },
    highRiskRate: { value: currentHigh, deltaPct: delta(currentHigh, previousHigh) },
  };
}
