export const CHART_COLORS = {
  blue: "#032ea1",
  red: "#e00025",
  redSoft: "rgba(224, 0, 37, 0.45)",
  ink: "#111111",
  inkSoft: "rgba(17, 17, 17, 0.4)",
  muted: "#666666",
  gridLine: "rgba(17, 17, 17, 0.08)",
};

const SERIES = [CHART_COLORS.blue, CHART_COLORS.ink, CHART_COLORS.muted, CHART_COLORS.inkSoft, CHART_COLORS.red];

export function seriesColor(index: number): string {
  return SERIES[index % SERIES.length];
}

export function riskColor(bucket: string): string {
  if (bucket === "Safe") return CHART_COLORS.blue;
  if (bucket === "Suspicious") return CHART_COLORS.redSoft;
  return CHART_COLORS.red;
}
