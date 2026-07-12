import type { APIRoute } from "astro";
import { db } from "../../../lib/server/db";

export const prerender = false;

export const GET: APIRoute = async ({ params }) => {
  const id = params.id ?? "";
  if (!/^[0-9a-f-]{36}$/i.test(id)) {
    return new Response("Not found", { status: 404 });
  }

  const rows = await db()<{
    mime_type: string;
    bytes: Uint8Array;
  }[]>`
    select mime_type, bytes
    from article_assets
    where id = ${id}
    limit 1
  `;

  const asset = rows[0];
  if (!asset) {
    return new Response("Not found", { status: 404 });
  }

  return new Response(asset.bytes, {
    headers: {
      "content-type": asset.mime_type,
      "cache-control": "public, max-age=31536000, immutable",
      "x-content-type-options": "nosniff",
    },
  });
};
