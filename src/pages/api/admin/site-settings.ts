import type { APIRoute } from "astro";
import { assertSameOrigin, requireAdmin } from "../../../lib/server/auth";
import { saveEditableSiteSettings } from "../../../lib/server/siteSettings";

export const prerender = false;

function text(form: FormData, key: string) {
  return String(form.get(key) ?? "").trim();
}

export const POST: APIRoute = async (context) => {
  if (!(await requireAdmin(context))) {
    return new Response("Unauthorized", { status: 401 });
  }

  try {
    assertSameOrigin(context.request);
    const form = await context.request.formData();
    await Promise.all([
      saveEditableSiteSettings("en", {
        heroTitle: text(form, "enHeroTitle"),
        heroBody: text(form, "enHeroBody"),
        ctaTitle: text(form, "enCtaTitle"),
        ctaBody: text(form, "enCtaBody"),
      }),
      saveEditableSiteSettings("kh", {
        heroTitle: text(form, "khHeroTitle"),
        heroBody: text(form, "khHeroBody"),
        ctaTitle: text(form, "khCtaTitle"),
        ctaBody: text(form, "khCtaBody"),
      }),
    ]);

    return context.redirect("/admin/site/");
  } catch (error) {
    const message = error instanceof Error ? error.message : "Could not save settings.";
    return new Response(message, { status: 400 });
  }
};
