import { DEFAULT_LOCALE, localizePath, type Locale } from "../data/site";
import { getDbArticle, getDbArticles, type DbArticle } from "./server/articles";

export type ContentCollection = "articles" | "tutorials";

type MarkdownModule = {
  frontmatter: Record<string, unknown>;
  Content: unknown;
};

export type MarkdownArticle = {
  id: string;
  collection: "articles";
  data: {
    title: string;
    description: string;
    date: Date;
    lang: Locale;
    translationId: string;
    tag: string;
    coverImage: string;
    draft: boolean;
  };
  Content: unknown;
};

export type MarkdownTutorial = {
  id: string;
  collection: "tutorials";
  data: {
    title: string;
    description: string;
    lang: Locale;
    translationId: string;
    coverImage: string;
    videoUrl?: string | null;
    draft: boolean;
  };
  Content: unknown;
};

export type SiteArticle = DbArticle | MarkdownArticle;

type EntryMap = {
  articles: MarkdownArticle;
  tutorials: MarkdownTutorial;
};

const articleModules = import.meta.glob<MarkdownModule>("../content/articles/*.md", {
  eager: true,
});
const tutorialModules = import.meta.glob<MarkdownModule>("../content/tutorials/*.md", {
  eager: true,
});

const tutorialOrder = [
  "forward-suspicious-message",
  "add-bot-to-group",
] as const;

function idFromPath(path: string) {
  return path.split("/").pop()?.replace(/\.md$/, "") ?? path;
}

function text(value: unknown) {
  return typeof value === "string" ? value : "";
}

function bool(value: unknown) {
  return typeof value === "boolean" ? value : false;
}

function locale(value: unknown): Locale {
  return value === "en" ? "en" : "kh";
}

function date(value: unknown) {
  return value instanceof Date ? value : new Date(String(value));
}

function markdownArticles() {
  return Object.entries(articleModules).map(([path, module]) => ({
    id: idFromPath(path),
    collection: "articles" as const,
    data: {
      title: text(module.frontmatter.title),
      description: text(module.frontmatter.description),
      date: date(module.frontmatter.date),
      lang: locale(module.frontmatter.lang),
      translationId: text(module.frontmatter.translationId),
      tag: text(module.frontmatter.tag),
      coverImage: text(module.frontmatter.coverImage),
      draft: bool(module.frontmatter.draft),
    },
    Content: module.Content,
  }));
}

function markdownTutorials() {
  return Object.entries(tutorialModules).map(([path, module]) => ({
    id: idFromPath(path),
    collection: "tutorials" as const,
    data: {
      title: text(module.frontmatter.title),
      description: text(module.frontmatter.description),
      lang: locale(module.frontmatter.lang),
      translationId: text(module.frontmatter.translationId),
      coverImage: text(module.frontmatter.coverImage),
      videoUrl: module.frontmatter.videoUrl ? text(module.frontmatter.videoUrl) : null,
      draft: bool(module.frontmatter.draft),
    },
    Content: module.Content,
  }));
}

export async function getLocalizedCollection<C extends ContentCollection>(
  collection: C,
  localeCode: Locale,
): Promise<EntryMap[C][]> {
  const entries =
    collection === "articles"
      ? markdownArticles().filter((entry) => entry.data.lang === localeCode && !entry.data.draft)
      : markdownTutorials().filter((entry) => entry.data.lang === localeCode && !entry.data.draft);

  if (collection === "articles") {
    return entries.sort((a, b) => {
      const articleA = a as MarkdownArticle;
      const articleB = b as MarkdownArticle;
      return articleB.data.date.getTime() - articleA.data.date.getTime();
    }) as EntryMap[C][];
  }

  return entries.sort((a, b) => {
    return (
      tutorialOrder.indexOf(a.data.translationId as (typeof tutorialOrder)[number]) -
      tutorialOrder.indexOf(b.data.translationId as (typeof tutorialOrder)[number])
    );
  }) as EntryMap[C][];
}

function articleDate(article: SiteArticle) {
  return "data" in article ? article.data.date : article.date;
}

export async function getLocalizedArticles(localeCode: Locale): Promise<SiteArticle[]> {
  const [markdownEntries, dbArticles] = await Promise.all([
    getLocalizedCollection("articles", localeCode),
    getDbArticles(localeCode),
  ]);

  return [...dbArticles, ...markdownEntries].sort(
    (a, b) => articleDate(b).getTime() - articleDate(a).getTime(),
  );
}

export async function getArticle(localeCode: Locale, slug: string): Promise<SiteArticle | null> {
  const dbArticle = await getDbArticle(localeCode, slug);
  if (dbArticle) {
    return dbArticle;
  }

  const markdownEntries = await getLocalizedCollection("articles", localeCode);
  return markdownEntries.find((entry) => entry.data.translationId === slug) ?? null;
}

export async function getTutorial(localeCode: Locale, slug: string) {
  const tutorials = await getLocalizedCollection("tutorials", localeCode);
  return tutorials.find((entry) => entry.data.translationId === slug) ?? null;
}

export async function getTranslatedEntry<C extends ContentCollection>(
  collection: C,
  translationId: string,
  localeCode: Locale,
): Promise<EntryMap[C] | undefined> {
  const entries = await getLocalizedCollection(collection, localeCode);
  return entries.find((entry) => entry.data.translationId === translationId);
}

export function getEntryUrl(
  collection: ContentCollection,
  localeCode: Locale,
  translationId: string,
) {
  return localizePath(localeCode, `${collection}/${translationId}`);
}

export function getAlternateLocale(localeCode: Locale): Locale {
  return localeCode === DEFAULT_LOCALE ? "en" : DEFAULT_LOCALE;
}
