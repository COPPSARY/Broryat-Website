import { marked } from "marked";
import sanitizeHtml from "sanitize-html";
import { db, hasDatabaseUrl, tableExists } from "./db";
import type { Locale } from "../../data/site";

export type DbArticle = {
  id: string;
  translationId: string;
  slug: string;
  lang: Locale;
  title: string;
  description: string;
  tag: string;
  coverImage: string;
  date: Date;
  bodyMarkdown: string;
  bodyHtml: string;
  status: "draft" | "published";
};

export type ArticleFormInput = {
  translationId: string;
  slug: string;
  status: "draft" | "published";
  tag: string;
  coverImageUrl?: string;
  en: {
    title: string;
    description: string;
    bodyHtml: string;
  };
  kh: {
    title: string;
    description: string;
    bodyHtml: string;
  };
};

export function slugify(value: string) {
  return value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 90);
}

export async function renderMarkdown(markdown: string) {
  const raw = await marked.parse(markdown, {
    async: true,
    gfm: true,
    breaks: true,
  });

  return sanitizeHtml(raw, {
    allowedTags: sanitizeHtml.defaults.allowedTags.concat(["img", "h1", "h2"]),
    allowedAttributes: {
      a: ["href", "name", "target", "rel"],
      img: ["src", "alt", "title", "loading"],
      code: ["class"],
    },
    allowedSchemes: ["http", "https", "mailto"],
    transformTags: {
      a: sanitizeHtml.simpleTransform("a", {
        rel: "noreferrer",
        target: "_blank",
      }),
      img: sanitizeHtml.simpleTransform("img", {
        loading: "lazy",
      }),
    },
  });
}

function mapArticle(row: {
  id: string;
  translation_id: string;
  slug: string;
  lang: Locale;
  title: string;
  description: string;
  tag: string;
  cover_asset_id: string | null;
  cover_image_url: string | null;
  published_at: Date | null;
  updated_at: Date;
  body_markdown: string;
  status: "draft" | "published";
  body_html: string | null;
}): DbArticle {
  return {
    id: row.id,
    translationId: row.translation_id,
    slug: row.slug,
    lang: row.lang,
    title: row.title,
    description: row.description,
    tag: row.tag,
    coverImage: row.cover_asset_id
      ? `/api/article-assets/${row.cover_asset_id}`
      : row.cover_image_url ?? "/branding/logo.png",
    date: row.published_at ?? row.updated_at,
    bodyMarkdown: row.body_markdown,
    bodyHtml: row.body_html ?? "",
    status: row.status,
  };
}

export async function getDbArticles(locale: Locale, includeDrafts = false) {
  if (!hasDatabaseUrl() || !(await tableExists("articles"))) {
    return [];
  }

  const rows = await db()<Parameters<typeof mapArticle>[0][]>`
    select id, translation_id, slug, lang, title, description, tag, cover_asset_id,
           cover_image_url, published_at, updated_at, body_markdown, status, body_html
    from articles
    where lang = ${locale}
      and (${includeDrafts} or status = 'published')
    order by coalesce(published_at, updated_at) desc
  `;

  return rows.map(mapArticle);
}

export async function getDbArticle(locale: Locale, slug: string, includeDrafts = false) {
  if (!hasDatabaseUrl() || !(await tableExists("articles"))) {
    return null;
  }

  const rows = await db()<Parameters<typeof mapArticle>[0][]>`
    select id, translation_id, slug, lang, title, description, tag, cover_asset_id,
           cover_image_url, published_at, updated_at, body_markdown, status, body_html
    from articles
    where lang = ${locale}
      and (slug = ${slug} or translation_id = ${slug})
      and (${includeDrafts} or status = 'published')
    limit 1
  `;

  return rows[0] ? mapArticle(rows[0]) : null;
}

export async function getDbArticlePair(translationId: string) {
  if (!hasDatabaseUrl() || !(await tableExists("articles"))) {
    return null;
  }

  const rows = await db()<Parameters<typeof mapArticle>[0][]>`
    select id, translation_id, slug, lang, title, description, tag, cover_asset_id,
           cover_image_url, published_at, updated_at, body_markdown, status, body_html
    from articles
    where translation_id = ${translationId}
    order by lang
  `;

  if (rows.length === 0) {
    return null;
  }

  const articles = rows.map(mapArticle);
  return {
    en: articles.find((article) => article.lang === "en") ?? null,
    kh: articles.find((article) => article.lang === "kh") ?? null,
  };
}

export async function saveArticlePair(input: ArticleFormInput, authorEmail: string) {
  const sql = db();
  const translationId = slugify(input.translationId) || slugify(input.en.title);
  const slug = slugify(input.slug) || translationId;
  const publishedAt = input.status === "published" ? new Date() : null;

  for (const lang of ["en", "kh"] as const) {
    const localized = input[lang];
    const isHtml = localized.bodyHtml.startsWith("<");
    const bodyHtml = isHtml ? localized.bodyHtml : await renderMarkdown(localized.bodyHtml);
    const bodyMarkdown = isHtml ? "" : localized.bodyHtml;

    await sql`
      insert into articles (
        translation_id, slug, lang, title, description, tag, cover_image_url,
        body_markdown, body_html, status, published_at, author_email
      )
      values (
        ${translationId}, ${slug}, ${lang}, ${localized.title}, ${localized.description},
        ${input.tag}, ${input.coverImageUrl || null}, ${bodyMarkdown}, ${bodyHtml},
        ${input.status}, ${publishedAt}, ${authorEmail}
      )
      on conflict (lang, translation_id)
      do update set
        slug = excluded.slug,
        title = excluded.title,
        description = excluded.description,
        tag = excluded.tag,
        cover_image_url = coalesce(excluded.cover_image_url, articles.cover_image_url),
        body_markdown = excluded.body_markdown,
        body_html = excluded.body_html,
        status = excluded.status,
        published_at = case
          when articles.published_at is null and excluded.status = 'published' then excluded.published_at
          else articles.published_at
        end,
        updated_at = now(),
        author_email = excluded.author_email
    `;
  }

  return { translationId, slug };
}
