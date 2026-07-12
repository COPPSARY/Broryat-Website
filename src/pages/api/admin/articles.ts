import type { APIRoute } from "astro";
import { assertSameOrigin, requireAdmin } from "../../../lib/server/auth";
import { saveArticlePair, slugify } from "../../../lib/server/articles";
import { createClient } from "@supabase/supabase-js";

export const prerender = false;

const MAX_COVER_BYTES = 4 * 1024 * 1024;
const ALLOWED_MIME = new Set(["image/png", "image/jpeg", "image/webp", "image/gif"]);

function required(form: FormData, key: string) {
  const value = String(form.get(key) ?? "").trim();
  if (!value) {
    throw new Error(`${key} is required.`);
  }
  return value;
}

export const POST: APIRoute = async (context) => {
  const session = await requireAdmin(context);
  if (!session) {
    return new Response("Unauthorized", { status: 401 });
  }

  try {
    assertSameOrigin(context.request);
    const form = await context.request.formData();
    const cover = form.get("cover");
    let coverImageUrl: string | undefined;

    if (cover instanceof File && cover.size > 0) {
      if (!ALLOWED_MIME.has(cover.type)) {
        return new Response("Unsupported cover image type.", { status: 400 });
      }
      if (cover.size > MAX_COVER_BYTES) {
        return new Response("Cover image must be 4MB or smaller.", { status: 400 });
      }

      const supabase = createClient(
        process.env.SUPABASE_URL!,
        process.env.SUPABASE_SERVICE_ROLE_KEY!,
        { auth: { persistSession: false, autoRefreshToken: false } },
      );

      const ext = cover.name.split(".").pop() || "png";
      const path = `covers/${slugify(required(form, "translationId")) || slugify(required(form, "enTitle"))}-${Date.now()}.${ext}`;

      const buffer = Buffer.from(await cover.arrayBuffer());
      const { error } = await supabase.storage
        .from("pictures")
        .upload(path, buffer, { contentType: cover.type, upsert: true });

      if (error) {
        throw new Error(`Cover upload failed: ${error.message}`);
      }

      const { data: urlData } = supabase.storage.from("pictures").getPublicUrl(path);
      coverImageUrl = urlData.publicUrl;
    }

    const enTitle = required(form, "enTitle");
    const translationId = slugify(required(form, "translationId")) || slugify(enTitle);
    const status = String(form.get("status") ?? "draft") === "published" ? "published" : "draft";

    await saveArticlePair(
      {
        translationId,
        slug: translationId,
        status,
        tag: required(form, "tag"),
        coverImageUrl,
        en: {
          title: enTitle,
          description: required(form, "enDescription"),
          bodyHtml: required(form, "enBody"),
        },
        kh: {
          title: required(form, "khTitle"),
          description: required(form, "khDescription"),
          bodyHtml: required(form, "khBody"),
        },
      },
      session.email,
    );

    return context.redirect("/admin/");
  } catch (error) {
    const message = error instanceof Error ? error.message : "Could not save article.";
    return new Response(message, { status: 400 });
  }
};
