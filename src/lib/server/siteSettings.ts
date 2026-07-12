import { db, hasDatabaseUrl, tableExists } from "./db";
import type { Locale } from "../../data/site";

export type EditableSiteSettings = {
  heroTitle?: string;
  heroBody?: string;
  ctaTitle?: string;
  ctaBody?: string;
};

export async function getEditableSiteSettings(locale: Locale) {
  if (!hasDatabaseUrl() || !(await tableExists("site_settings"))) {
    return {};
  }

  const rows = await db()<{
    value: EditableSiteSettings;
  }[]>`
    select value
    from site_settings
    where key = ${`home.${locale}`}
    limit 1
  `;

  return rows[0]?.value ?? {};
}

export async function saveEditableSiteSettings(locale: Locale, value: EditableSiteSettings) {
  await db()`
    insert into site_settings (key, value)
    values (${`home.${locale}`}, ${JSON.stringify(value)}::jsonb)
    on conflict (key)
    do update set value = excluded.value, updated_at = now()
  `;
}
