import "dotenv/config";
import { createClient } from "@supabase/supabase-js";
import type { APIContext, AstroGlobal } from "astro";
import { db } from "./db";

export const ACCESS_COOKIE = "broryat_admin_access";
export const REFRESH_COOKIE = "broryat_admin_refresh";
export const MAX_AGE_SECONDS = 60 * 60 * 8;

export type AdminSession = {
  userId: string;
  email: string;
};

export function getSupabaseClient() {
  const url = process.env.SUPABASE_URL;
  const anonKey = process.env.SUPABASE_ANON_KEY;

  if (!url || !anonKey) {
    throw new Error("SUPABASE_URL and SUPABASE_ANON_KEY must be configured.");
  }

  return createClient(url, anonKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });
}

async function isAdmin(userId: string, email: string) {
  const rows = await db()<{
    is_active: boolean;
  }[]>`
    select is_active
    from admin_profiles
    where is_active = true
      and (auth_user_id = ${userId}::uuid or lower(email) = lower(${email}))
    limit 1
  `;

  return rows[0]?.is_active === true;
}

export async function login(email: string, password: string) {
  const supabase = getSupabaseClient();
  const { data, error } = await supabase.auth.signInWithPassword({
    email,
    password,
  });

  if (error || !data.session || !data.user?.email) {
    console.error("Supabase admin login failed:", error?.message ?? "No session returned.");
    return null;
  }

  if (!(await isAdmin(data.user.id, data.user.email))) {
    console.error("Supabase user is not allowlisted for admin:", data.user.email);
    return null;
  }

  return {
    accessToken: data.session.access_token,
    refreshToken: data.session.refresh_token,
  };
}

export function setSessionCookie(
  context: APIContext | AstroGlobal,
  session: { accessToken: string; refreshToken: string },
) {
  const url = new URL(context.request.url);
  const isSecure = url.protocol === "https:";

  const options = {
    httpOnly: true,
    secure: isSecure,
    sameSite: "lax" as const,
    path: "/",
    maxAge: MAX_AGE_SECONDS,
  };

  context.cookies.set(ACCESS_COOKIE, session.accessToken, options);
  context.cookies.set(REFRESH_COOKIE, session.refreshToken, options);
}

export function clearSessionCookie(context: APIContext | AstroGlobal) {
  context.cookies.delete(ACCESS_COOKIE, { path: "/" });
  context.cookies.delete(REFRESH_COOKIE, { path: "/" });
}

export async function requireAdmin(context: APIContext | AstroGlobal): Promise<AdminSession | null> {
  const accessToken = context.cookies.get(ACCESS_COOKIE)?.value;
  if (!accessToken) {
    return null;
  }

  const supabase = getSupabaseClient();
  const { data, error } = await supabase.auth.getUser(accessToken);
  const email = data.user?.email;

  if (error || !data.user || !email) {
    return null;
  }

  if (!(await isAdmin(data.user.id, email))) {
    return null;
  }

  return {
    userId: data.user.id,
    email,
  };
}

export function assertSameOrigin(request: Request) {
  const origin = request.headers.get("origin");
  const host = request.headers.get("host");
  if (!origin || !host) {
    return;
  }

  const originUrl = new URL(origin);
  if (originUrl.host !== host) {
    throw new Error("Invalid request origin.");
  }
}
