import type { APIRoute } from "astro";
import { assertSameOrigin, requireAdmin } from "../../../lib/server/auth";
import { slugify } from "../../../lib/server/articles";
import { createClient } from "@supabase/supabase-js";

export const prerender = false;

const MAX_BYTES = 5 * 1024 * 1024;
const ALLOWED_MIME = new Set(["image/png", "image/jpeg", "image/webp", "image/gif"]);

export const POST: APIRoute = async (context) => {
  const session = await requireAdmin(context);
  if (!session) return new Response("Unauthorized", { status: 401 });

  try {
    assertSameOrigin(context.request);
    const form = await context.request.formData();
    const file = form.get("file");

    if (!(file instanceof File) || file.size === 0) {
      return new Response("No file provided.", { status: 400 });
    }
    if (!ALLOWED_MIME.has(file.type)) {
      return new Response("Unsupported image type.", { status: 400 });
    }
    if (file.size > MAX_BYTES) {
      return new Response("Image must be 5MB or smaller.", { status: 400 });
    }

    const supabase = createClient(
      process.env.SUPABASE_URL!,
      process.env.SUPABASE_SERVICE_ROLE_KEY!,
      { auth: { persistSession: false, autoRefreshToken: false } },
    );

    const ext = file.name.split(".").pop() || "png";
    const path = `inline/${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;
    const buffer = Buffer.from(await file.arrayBuffer());

    const { error } = await supabase.storage
      .from("pictures")
      .upload(path, buffer, { contentType: file.type, upsert: false });

    if (error) throw new Error(error.message);

    const { data: urlData } = supabase.storage.from("pictures").getPublicUrl(path);

    return new Response(JSON.stringify({ url: urlData.publicUrl }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Upload failed.";
    return new Response(msg, { status: 500 });
  }
};
